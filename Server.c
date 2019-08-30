
#include "sood_auth_proto.h"
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>

/*about the mbedtls configuration*/
#if !defined(MBEDTLS_CONFIG_FILE)
 #include "mbedtls/config.h"
#else
 #include MBEDTLS_CONFIG_FILE
#endif
/*******************************************************************************
 * Enable the platform abstraction layer that allows you to re-assign
 * functions like calloc(), free(), snprintf(), printf(), fprintf(), exit().
 *******************************************************************************/
#if defined(MBEDTLS_PLATFORM_C)
 #include "mbedtls/platform.h"
#else
 #include <stdio.h>
 #define mbedtls_printf 		printf
 #define mbedtls_fprintf		fprintf
#endif 
/********************Enable the MD5 hash algorithm.******************************/
#if defined(MBEDTLS_MD5_C)
 #include "mbedtls/md5.h"
#endif
/*******************************************************************************
 * MBEDTLS_CTR_DRBG_C
 * Enable the CTR_DRBG AES-256-based random generator.
 *
 * MBEDTLS_ENTROPY_C
 * Enable the platform-specific entropy code.(平均信息量编码)
 * 
 * MBEDTLS_FS_IO
 * Enable functions that use the filesystem.
 ******************************************************************************/
#if defined(MBEDTLS_CTR_DRBG_C) && defined(MBEDTLS_ENTROPY_C) && \
 defined(MBEDTLS_FS_IO)
 #include "mbedtls/entropy.h"
 #include "mbedtls/ctr_drbg.h"
 #include <stdio.h>
#endif

#define 	SERVER_PORT		9737

char *serverSrt = "127.0.0.1:9737";

unsigned char digest_SID[16];
unsigned char digest_SID_y[16];
unsigned char digest_x_y[16];
unsigned char rng_Ni2[16];

int random_nunber_init(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy){
	int ret;
	/*CTR_DRBG context initialization Makes the context ready for mbedtls_ctr_drbg_seed() or mbedtls_ctr_drbg_free()*/
	mbedtls_ctr_drbg_init( ctr_drbg );
	/************Initialize the context***********/
	mbedtls_entropy_init( entropy );
	/**CTR_DRBG initial seeding Seed and setup entropy source for future reseeds.（生成随机数种子）详情见mbedtls帮助文档
	* "RANDOM_GEN" 为个性化数据，添加这个参数使得种子生成更加独特                                                   */
	ret = mbedtls_ctr_drbg_seed( ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *) "SERVER_GEN",sizeof("SERVER_GEN") );
	if( 0 != ret ){
		mbedtls_printf( "failed in mbedtls_ctr_drbg_seed : ret = %d\n", ret);
		mbedtls_printf( "failed in random number general seed.\n" );
		return -1;
	}
	/*Enable / disable prediction resistance 设置随机数抗预测*/
	mbedtls_ctr_drbg_set_prediction_resistance( ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );
	return 0;
}	

int registion_for_Center(const auth_proto_msg *auth_rece_msg){
	char filePath[128];
	FILE *localFile;

	mbedtls_printf("registion for control center.\n");
	mbedtls_printf("extract h(SID||y) and h(x||y)...\n");

	memcpy( digest_SID_y, auth_rece_msg->message ,sizeof(digest_SID_y));
	memcpy( digest_x_y, auth_rece_msg->message + sizeof(digest_SID_y) ,sizeof(digest_x_y));

	mbedtls_printf("the h(SID||y) = ");
	print_128bits(digest_SID_y);
	mbedtls_printf("the h(x||y) = ");
	print_128bits(digest_x_y);
	mbedtls_printf("Write h(SID||y) and h(x||y) to local database.\n");

	memset( filePath, 0, sizeof(filePath));
	strcat( filePath, "");
	strcat( filePath, "Server_Data/local");
	localFile = fopen(filePath,"w+");
	fwrite( auth_rece_msg->message, sizeof(unsigned char), auth_rece_msg->msg_len, localFile);
	fclose( localFile );
	return 0;
}

int authentication_for_user(mbedtls_ctr_drbg_context *ctr_drbg, const auth_proto_msg *auth_rece_msg){
	unsigned char digest_K[16];
	unsigned char digest_M[16];
	unsigned char digest_tmp[16];
	unsigned char tmp_cmput[128];
	unsigned int cmput_len = 0;

	char buff[1024];
	unsigned int buff_len;

	int cs_sockfd = -1;
	int cs_port = 9736;
	struct sockaddr_in cs_addr;

	auth_proto_msg auth_send_msg;

	FILE *localFile;
	int ret;
	
	mbedtls_ctr_drbg_random( ctr_drbg, rng_Ni2, sizeof(rng_Ni2) );

	localFile =  fopen("Server_Data/local","rb+");
	memset( tmp_cmput, 0, sizeof(tmp_cmput));
	ret = fread( tmp_cmput,sizeof(unsigned char), 2*16, localFile );
	fclose( localFile );

	/*********************************存储Ni2******************************************/

	localFile = fopen("Server_Data/tmpfile","wb+");
	fwrite( rng_Ni2, sizeof(unsigned char), sizeof(rng_Ni2), localFile);
	fclose( localFile );

	/********************从本地的local文件中提取出h(SID||y),h(x||y)信息****************/
	memcpy( digest_SID_y, tmp_cmput, sizeof(digest_SID_y) );
	memcpy( digest_x_y, tmp_cmput + sizeof(digest_SID_y), sizeof(digest_x_y) );

	/*********************************计算digest_K*************************************/
	XOR_128bits( digest_SID_y, rng_Ni2 , digest_K);

	/*********************************计算digest_M*************************************/
	memset( tmp_cmput, 0, sizeof(tmp_cmput) );
	cmput_len = 0;
	memcpy( tmp_cmput + cmput_len, digest_x_y, sizeof(digest_x_y) );
	cmput_len += sizeof(digest_x_y);
	memcpy( tmp_cmput + cmput_len, rng_Ni2, sizeof(rng_Ni2) );
	cmput_len += sizeof(rng_Ni2);
	mbedtls_md5( tmp_cmput, cmput_len, digest_tmp);
	mbedtls_md5( digest_tmp, sizeof(digest_tmp), digest_M);

	mbedtls_printf("STEP1: Exchang Key Phase");
	mbedtls_printf("\tfrom file read digest_SID_y = ");
	print_128bits(digest_SID_y);
	mbedtls_printf("\tfrom file read digest_x_y   = ");
	print_128bits(digest_x_y);
	mbedtls_printf("\tserver generate rng_Ni2     = ");
	print_128bits(rng_Ni2);
	mbedtls_printf("\tthe sent digest_K           = ");
	print_128bits(digest_K);
	mbedtls_printf("\tthe sent digest_M           = ");
	print_128bits(digest_M);


	/**************************构造发送数据********************************************/
	memset( buff, 0, sizeof(buff));
	buff_len = 0;
	memcpy(buff + buff_len, auth_rece_msg->message, auth_rece_msg->msg_len);
	buff_len += auth_rece_msg->msg_len;
	memcpy(buff + buff_len, digest_SID, sizeof(digest_SID));
	buff_len += sizeof(digest_SID);
	memcpy(buff + buff_len, digest_K, sizeof(digest_K));
	buff_len += sizeof(digest_K);
	memcpy(buff + buff_len, digest_M, sizeof(digest_M));
	buff_len += sizeof(digest_M);

	auth_send_msg.phase = AUTH_PROTO_PHASE_EXHANGEKEY;
	memset(auth_send_msg.message, 0, 128);
	memcpy(auth_send_msg.message, buff, buff_len);
	auth_send_msg.msg_len = buff_len;

	memset( buff, 0, sizeof(buff) );
	buff_len = 0;
	memcpy( buff, &auth_send_msg, sizeof(auth_proto_msg));
	buff_len += sizeof(auth_send_msg);

	cs_sockfd = socket( AF_INET, SOCK_STREAM, 0 );
	cs_addr.sin_family = AF_INET;
	cs_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	cs_addr.sin_port = htons(cs_port);

	ret = connect( cs_sockfd, (struct sockaddr *)&cs_addr, sizeof(cs_addr) );
	if(-1 == ret ){
		mbedtls_printf( "error in Server: can't connect to control center.\n");
		return -1;
	}else{
		ret = write( cs_sockfd, buff, buff_len);
		if( -1 == ret ){
			mbedtls_printf( "erorr in sock write: failed to send (Fi,Gi,Pij,CIDi,SIDj,Ki,Mi).\n" );
			close(cs_sockfd);
			return -1;
		}else{
			mbedtls_printf( "\tsent authentication message of (Fi,Gi,Pij,CIDi,SIDj,Ki,Mi) to Control Center.\n" );
			close(cs_sockfd);
			return 0;
		}

	}

	return 0;
}

int authentication_for_CtrlCenter(auth_proto_msg *auth_rece_msg){

	int ret;
	char buff[1024];
	unsigned int buff_len = 0;

	FILE *localFile;

	int smartCard_sockfd;
	struct sockaddr_in smartCard_address;
	int smartCard_port = 9738;


	unsigned char tmp_cmput[128];
	unsigned int cmput_len = 0;
	unsigned char tmp_xor[16];
	unsigned char tmp_digest[16];

	unsigned char digest_Q[16];
	unsigned char digest_R[16];
	unsigned char digest_V[16];
	unsigned char digest_T[16];
	unsigned char digest_Vi[16];
	unsigned char rngNi1_xor_rngNi3[16];
	unsigned char digest_A_B[16];
	unsigned char SK[16];

	auth_proto_msg auth_send_msg;

	localFile = fopen("Server_Data/tmpfile","rb+");
	ret = fread( rng_Ni2, sizeof(unsigned char), sizeof(rng_Ni2), localFile);
	if( ret != sizeof(rng_Ni2)){
		mbedtls_printf(" read Ni2 error!.\n");
	}

	buff_len = 0;
	memcpy(digest_Q, auth_rece_msg->message + buff_len, sizeof(digest_Q));
	buff_len += sizeof(digest_Q);
	memcpy(digest_R, auth_rece_msg->message + buff_len, sizeof(digest_R));
	buff_len += sizeof(digest_R);
	memcpy(digest_V, auth_rece_msg->message + buff_len, sizeof(digest_V));
	buff_len += sizeof(digest_V);
	memcpy(digest_T, auth_rece_msg->message + buff_len, sizeof(digest_T));
	buff_len += sizeof(digest_T);
	mbedtls_printf("STEP5: Exchang Key Phase\n");
	mbedtls_printf("\tfrom the auth_rece_msg read the digest of message.\n");
	mbedtls_printf("\tthe read digest_Q = ");
	print_128bits(digest_Q);
	mbedtls_printf("\tthe read digest_R = ");
	print_128bits(digest_R);
	mbedtls_printf("\tthe read digest_V = ");
	print_128bits(digest_V);
	mbedtls_printf("\tthe read digest_T = ");
	print_128bits(digest_T);

	/****************************计算Ni1xorNi3********************************/
	memset( tmp_cmput, 0, sizeof(tmp_cmput) );
	cmput_len = 0;
	memcpy( tmp_cmput + cmput_len, digest_SID, sizeof(digest_SID) );
	cmput_len += sizeof(digest_SID);
	memcpy( tmp_cmput + cmput_len, rng_Ni2 ,sizeof(rng_Ni2));
	cmput_len += sizeof(rng_Ni2);
	mbedtls_md5( tmp_cmput, cmput_len, tmp_xor);
	XOR_128bits( tmp_xor, digest_Q, rngNi1_xor_rngNi3);
	/*************************************************************************/

	mbedtls_printf("\tthe digest_SID    = ");
	print_128bits(digest_SID);
	mbedtls_printf("\tthe rng_Ni2       = ");
	print_128bits(rng_Ni2);

	/*****************************计算h(A||B)*********************************/
	XOR_128bits( rngNi1_xor_rngNi3, rng_Ni2, tmp_xor);
	mbedtls_md5( tmp_xor, sizeof(tmp_xor), tmp_digest);
	XOR_128bits( tmp_digest, digest_R, digest_A_B);

	/*****************************计算V'***************************************/
	XOR_128bits( rngNi1_xor_rngNi3, rng_Ni2, tmp_xor );
	mbedtls_md5( tmp_xor, sizeof(tmp_xor), tmp_digest);

	memset( tmp_cmput, 0, sizeof(tmp_cmput) );
	cmput_len = 0;
	memcpy( tmp_cmput + cmput_len, digest_A_B, sizeof(digest_A_B));
	cmput_len += sizeof(digest_A_B);
	memcpy( tmp_cmput + cmput_len, tmp_digest, sizeof(tmp_digest));
	cmput_len += sizeof(tmp_digest);
	mbedtls_md5( tmp_cmput, cmput_len,digest_Vi);

	mbedtls_printf("\tthe Computed (Ni1 or Ni3) = ");
	print_128bits(rngNi1_xor_rngNi3);
	mbedtls_printf("\tthe Computed digest_A_B   = ");
	print_128bits(digest_A_B);
	mbedtls_printf("\tthe server Computed h(Ni1 or Ni2 or Ni3) = ");
	print_128bits(tmp_digest);

	ret = memcmp( digest_V , digest_Vi, sizeof(digest_V));
	if( 0 == ret){
		mbedtls_printf( "\tdigest_V is euqal to digest_Vi: V = V'.\n" );
		mbedtls_printf( "\tControl center authenticated by server.\n" );
		

		/*****************************计算最终协商出的密钥SK***********************/
		XOR_128bits(rngNi1_xor_rngNi3, rng_Ni2, tmp_xor);

		memset( tmp_cmput, 0, sizeof(tmp_cmput) );
		cmput_len = 0;
		memcpy( tmp_cmput + cmput_len, digest_A_B, sizeof(digest_A_B) );
		cmput_len += sizeof(digest_A_B);
		memcpy( tmp_cmput + cmput_len, tmp_xor, sizeof(tmp_xor) );
		cmput_len += sizeof(tmp_xor);
		mbedtls_md5( tmp_cmput, cmput_len, SK);

		mbedtls_printf( "\tThe Final Exchang-Key = ");
		print_128bits(SK);
		
		/***************************构造发送数据************************************/
		memset( buff, 0, sizeof(buff) );
		buff_len = 0;
		memcpy( buff + buff_len, digest_V, sizeof(digest_V) );
		buff_len += sizeof(digest_V);
		memcpy( buff + buff_len, digest_T, sizeof(digest_T) );
		buff_len += sizeof(digest_T);

		auth_send_msg.phase = AUTH_PROTO_PHASE_EXHANGEKEY;
		memcpy(auth_send_msg.message, buff, buff_len);
		auth_send_msg.msg_len = buff_len;

		memset( buff, 0, sizeof(buff) );
		buff_len = 0;
		memcpy( buff, &auth_send_msg, sizeof(auth_proto_msg));
		buff_len += sizeof(auth_proto_msg);

		smartCard_sockfd = socket(AF_INET,SOCK_STREAM,0);
		smartCard_address.sin_family = AF_INET;
		smartCard_address.sin_addr.s_addr = inet_addr("127.0.0.1");
		smartCard_address.sin_port = htons(smartCard_port);

		ret = connect( smartCard_sockfd, (struct sockaddr *)&smartCard_address, sizeof(smartCard_address));
		if( -1 == ret ){
			mbedtls_printf("error in send (Vi,Ti):can't connect the smartCard.\n");
			close( smartCard_sockfd );
			return -1;
		}else{
			ret = write( smartCard_sockfd, buff, buff_len);
			if( -1 == ret){
				mbedtls_printf("error in send (Vi,Ti):can't write the message to smartCard_sock.\n");
				close( smartCard_sockfd );
			}
			mbedtls_printf("\tsent authenticated message (Vi,Ti) to smartCard.\n");
			close( smartCard_sockfd );
			return 0;
		}
	}else{
		mbedtls_printf( "digest_V is not euqal to digest_Vi: V != V'.\n" );
		mbedtls_printf( "Control center not authenticated by server.\n" );
		return -1;
	}
}


/****************检查mbedtls随机数模块和加密模块配置是否打开******************/
#if !defined(MBEDTLS_CTR_DRBG_C) || !defined(MBEDTLS_ENTROPY_C) || \
 !defined(MBEDTLS_FS_IO)
int main( void ){
    mbedtls_printf("MBEDTLS_CTR_DRBG_C and/or MBEDTLS_ENTROPY_C and/or MBEDTLS_FS_IO not defined.\n");
    mbedtls_printf("Computer can't generat random number and encrpty the plaintext.\n");
    mbedtls_printf("Plese check /usr/local/include/mbedtls/config to enable them.\n");
    return( 0 );
}
#else
int main ( void ){

	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

	int server_socketfd = -1;
	int client_socketfd = -1;
	unsigned int client_len = 0;
	struct sockaddr_in server_addr;
	struct sockaddr_in client_addr;
	int ret = 0;

	char sock_buff[1024];
//	int sock_buff_len = 0;

	auth_proto_msg receive_auth_message;

	/***********************************创建流式套接字***************************/
	server_socketfd = socket(AF_INET,SOCK_STREAM,0);

	/********************设置服务器接收连接地址和监听端口************************/
	server_addr.sin_family = AF_INET; //使用IPv4协议            
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY); //接受来自任何地址的请求
	server_addr.sin_port = htons(SERVER_PORT);	//开放的服务端口号

	//绑定套接字
	bind(server_socketfd,(struct sockaddr *)&server_addr,sizeof(server_addr));
	listen(server_socketfd,15);

	random_nunber_init( &ctr_drbg , &entropy );

	/**************************************生成digest——SID**********************/
	mbedtls_md5((unsigned char *)serverSrt,strlen(serverSrt),digest_SID);
	mbedtls_printf(" server published digest_SID = ");
	print_128bits(digest_SID);

	while(1){
		client_len = sizeof(client_addr);
		mbedtls_printf("Server is listening ...\n");
		client_socketfd = accept( server_socketfd, (struct sockaddr *)&client_addr, &client_len );
		if( 0 == fork()){
			mbedtls_printf("receive a connection ...\n");
			ret =  read( client_socketfd, sock_buff,sizeof(sock_buff));
			if( -1 == ret){
				mbedtls_printf("error in read message.\n");
				exit(-1);
			}
			memset( &receive_auth_message, 0, sizeof(auth_proto_msg));
			memcpy( &receive_auth_message,sock_buff,sizeof(auth_proto_msg));

			if( AUTH_PROTO_PHASE_LOGIN == receive_auth_message.phase){
				authentication_for_user( &ctr_drbg, &receive_auth_message);
			}else if(AUTH_PROTO_PHASE_REGISTION == receive_auth_message.phase){
				registion_for_Center( &receive_auth_message );
			}else if(AUTH_PROTO_PHASE_EXHANGEKEY == receive_auth_message.phase){
				
				authentication_for_CtrlCenter( &receive_auth_message );
			}else{
				mbedtls_printf("An unknowed   occured. \n");
				exit(0);
			}
			close(client_socketfd);
			exit(0);
		}else{
			close(client_socketfd);
		}
	}

}

#endif
