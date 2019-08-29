
#include "sood_auth_proto.h"

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>


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

#define 	CS_PORT   	9736
#define 	SERVER_PORT 9737

/****************************cecret x generate by MD5("ControlCenter")*************
*MD5("ControlCenter")=84 4c 61 e4 3c 7b 0d fc ef 08 8f 9f 4b e8 77 d9
***********************************************************************************/
static unsigned char cecret_x[16] = {0x84,0x4c,0x61,0xe4,0x3c,0x7b,0x0d,0xfc,
						 		  0xef,0x08,0x8f,0x9f,0x4b,0xe8,0x77,0xd9};

/****************************cecret y generate by MD5("Authentication")*************
*MD5("Authentication")=c7 5f 78 11 d7 0d 17 db cd 88 e9 d0 37 52 cb ed
***********************************************************************************/					 
static unsigned char cecret_y[16] = {0xc7,0x5f,0x78,0x11,0xd7,0x0d,0x17,0xdb,
				 		 		  0xcd,0x88,0xe9,0xd0,0x37,0x52,0xcb,0xed};

char *serverSrt = "127.0.0.1:9737"; 

unsigned char digest_SID_y[16];
unsigned char digest_y[16];
unsigned char digest_x_y[16];
unsigned char digest_SID[16];
unsigned char rng_Ni3[16];


int random_nunber_init(mbedtls_ctr_drbg_context *ctr_drbg, mbedtls_entropy_context *entropy){
	int ret;

	/*CTR_DRBG context initialization Makes the context ready for mbedtls_ctr_drbg_seed() or mbedtls_ctr_drbg_free()*/
	mbedtls_ctr_drbg_init( ctr_drbg );

	/************Initialize the context***********/
	mbedtls_entropy_init( entropy );

	/**CTR_DRBG initial seeding Seed and setup entropy source for future reseeds.（生成随机数种子）详情见mbedtls帮助文档
	* "RANDOM_GEN" 为个性化数据，添加这个参数使得种子生成更加独特                                                   */
	ret = mbedtls_ctr_drbg_seed( ctr_drbg, mbedtls_entropy_func, entropy, (const unsigned char *) "RANDOM_GEN",sizeof("RANDOM_GEN") );
	if( 0 != ret ){
		mbedtls_printf( "failed in mbedtls_ctr_drbg_seed : ret = %d\n", ret);
		mbedtls_printf( "failed in random number general seed.\n" );
		return -1;
	}

	/*Enable / disable prediction resistance 设置随机数抗预测*/
	mbedtls_ctr_drbg_set_prediction_resistance( ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );

	return 0;
}

int send_sharemessage_to_server(){
	int server_sockfd = -1;
	int ret;
	struct sockaddr_in server_addr;

	unsigned char tmp_cmput[128];
	unsigned char cmput_len = 0;

	char sock_buff[1024];
	unsigned int sock_buff_len = 0;

	mbedtls_printf("Before Authentication Protocal share digest of some message.\n");

	auth_proto_msg auth_message;
	/*******************计算h(y||x)*************************************************/
	memset(tmp_cmput, 0, sizeof(tmp_cmput));
	cmput_len = 0;
	memcpy(tmp_cmput + cmput_len, cecret_y, sizeof(cecret_y));
	cmput_len += sizeof(cecret_y);
	memcpy(tmp_cmput + cmput_len, cecret_x, sizeof(cecret_x));
	cmput_len += sizeof(cecret_x);
	mbedtls_md5(tmp_cmput,cmput_len,digest_x_y);
	/*******************计算h(x||y)*************************************************/

	/*******************计算h(SID||y)***********************************************/
	mbedtls_md5((unsigned char *)serverSrt, strlen(serverSrt), digest_SID);

	memset(tmp_cmput, 0, sizeof(tmp_cmput));
	cmput_len = 0;
	memcpy(tmp_cmput + cmput_len, digest_SID, sizeof(digest_SID));
	cmput_len += sizeof(digest_SID);
	memcpy(tmp_cmput + cmput_len, cecret_y, sizeof(cecret_y));
	cmput_len += sizeof(cecret_y);
	mbedtls_md5(tmp_cmput,cmput_len,digest_SID_y);
	/*******************计算h(SID||y)***********************************************/

	/********************************计算出h(y)*************************************/
	mbedtls_md5(cecret_y,sizeof(cecret_y),digest_y);

	mbedtls_printf( "the digest_SID   = " );
	print_128bits(digest_SID);
	mbedtls_printf( "the digest_SID_y = " );
	print_128bits( digest_SID_y );
	mbedtls_printf( "the digest_x_y = " );
	print_128bits( digest_x_y );
	
	memset(sock_buff, 0, sizeof(sock_buff));
	sock_buff_len = 0;
	memcpy(sock_buff + sock_buff_len, digest_SID_y, sizeof(digest_SID_y));
	sock_buff_len += sizeof(digest_SID_y);
	memcpy(sock_buff + sock_buff_len, digest_x_y, sizeof(digest_x_y));
	sock_buff_len += sizeof(digest_x_y);
	
	auth_message.phase = AUTH_PROTO_PHASE_REGISTION;
	memcpy( auth_message.message, sock_buff, sock_buff_len );
	auth_message.msg_len = sock_buff_len;

	memset(sock_buff, 0, sizeof(sock_buff));
	sock_buff_len = 0;
	memcpy(sock_buff, &auth_message, sizeof(auth_proto_msg));
	sock_buff_len += sizeof(auth_proto_msg);
	
	server_sockfd = socket( AF_INET,SOCK_STREAM,0);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(SERVER_PORT);

	ret = connect( server_sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr));
	if( -1 == ret){
		mbedtls_printf("Control Center can't connect the server .\n");
		return -1;
	}else{
		ret = write( server_sockfd, sock_buff, sock_buff_len);
		if( -1 == ret){
			mbedtls_printf( "in send_sharemessage_to_server: failed to write message to server.\n" );
			return -1;
		}
	}
	return 0;
}


int registion_for_user(const auth_proto_msg *auth_rece_msg, auth_proto_msg *auth_send_msg){

	unsigned char digest_A[16];
	unsigned char digest_B[16];
	unsigned char digest_C[16];
	unsigned char digest_D[16];
	unsigned char digest_E[16];
	unsigned char digest_y[16];
	char ID[16];

	FILE *user_data_file;
	char filepath[96];

	char send_buff[1024];
	int sned_len = 0;

	unsigned char tmp_xor[16];
	unsigned char tmp_cmput[128];
	int hash_length = 0;
	
	/*计算变量全部清零*/
	memset(digest_A,0,sizeof(digest_A));
	memset(digest_B,0,sizeof(digest_B));
	memset(digest_C,0,sizeof(digest_C));
	memset(digest_D,0,sizeof(digest_D));
	memset(digest_E,0,sizeof(digest_E));

	/*取出传送过来的ID和Ai数据*/
	memcpy(digest_A,auth_rece_msg->message,sizeof(digest_A));
	memcpy(ID,auth_rece_msg->message+sizeof(digest_A),auth_rece_msg->msg_len-sizeof(digest_A));

	mbedtls_printf("STEP2: User Registion Phase\n");
	mbedtls_printf("\tthe recieved ID is %s.\n",ID);
	mbedtls_printf("\tthe recieved digest_A = ");
	print_128bits(digest_A);
		
	/*****************************计算Bi************************************/
	memset(tmp_cmput,0,sizeof(tmp_cmput));
	hash_length = 0;
	memcpy(tmp_cmput,ID,strlen(ID));
	hash_length += strlen(ID);
	memcpy(tmp_cmput+hash_length,cecret_x,sizeof(cecret_x));
	hash_length += sizeof(cecret_x);
	mbedtls_md5(tmp_cmput,hash_length,digest_B);
	/***********************************************************************/

	/*****************************计算Ci************************************/
	memset(tmp_cmput,0,sizeof(tmp_cmput));
	hash_length = 0;
	memcpy(tmp_cmput,ID,strlen(ID));
	hash_length += strlen(ID);
	memset(digest_y,0,sizeof(digest_y));
	mbedtls_md5(cecret_y,sizeof(cecret_y),digest_y);
	memcpy(tmp_cmput + hash_length,digest_y,sizeof(digest_y));
	hash_length += sizeof(digest_y);
	memcpy(tmp_cmput + hash_length,digest_A,sizeof(digest_A));
	hash_length += sizeof(digest_A);
	mbedtls_md5(tmp_cmput,hash_length,digest_C);
	/*****************************计算Ci************************************/

	/*****************************计算Di************************************/
	memset(tmp_cmput,0,sizeof(tmp_cmput));
	hash_length = 0;
	memcpy(tmp_cmput,ID,strlen(ID));
	hash_length += strlen(ID);
	memcpy(tmp_cmput+hash_length,digest_A,sizeof(digest_A));
	hash_length += sizeof(digest_A);
	memset(tmp_xor,0,sizeof(tmp_xor));
	mbedtls_md5(tmp_cmput,hash_length,tmp_xor);
	XOR_128bits(tmp_xor,digest_B,digest_D);
	/*****************************计算Di************************************/

	/*****************************计算Ei************************************/
	memset(tmp_cmput,0,sizeof(tmp_cmput));
	hash_length = 0;
	memcpy(tmp_cmput,cecret_y,sizeof(cecret_y));
	hash_length += sizeof(cecret_y);
	memcpy(tmp_cmput+hash_length,cecret_x,sizeof(cecret_x));
	hash_length += sizeof(cecret_x);
	memset(tmp_xor,0,sizeof(tmp_xor));
	mbedtls_md5(tmp_cmput,hash_length,tmp_xor);
	XOR_128bits(tmp_xor,digest_B,digest_E);
	/*****************************计算Ei************************************/

	/*****************************打印调试信息******************************/
	mbedtls_printf("\tthe computed digest_B = ");
	print_128bits(digest_B);
	mbedtls_printf("\tthe computed digest_C = ");
	print_128bits(digest_C);
	mbedtls_printf("\tthe computed digest_D = ");
	print_128bits(digest_D);
	mbedtls_printf("\tthe computed digest_E = ");
	print_128bits(digest_E);
	/************************************************************************/

	/*******************************构造发送数据******************************/
	memset(auth_send_msg,0,sizeof(auth_proto_msg));
	auth_send_msg->phase = AUTH_PROTO_PHASE_REGISTION;
	memset(send_buff,0,sizeof(send_buff));
	sned_len = 0;
	memcpy(send_buff,digest_C,sizeof(digest_C));
	sned_len += sizeof(digest_C);
	memcpy(send_buff+sned_len,digest_D,sizeof(digest_D));
	sned_len += sizeof(digest_D);
	memcpy(send_buff+sned_len,digest_E,sizeof(digest_E));
	sned_len += sizeof(digest_E);
	memcpy(send_buff+sned_len,digest_y,sizeof(digest_y));
	sned_len += sizeof(digest_y);
	memset(auth_send_msg->message,0,128);
	memcpy(auth_send_msg->message,send_buff,sned_len);
	auth_send_msg->msg_len = sned_len;

	/***********存储用户数据************/
	strcpy(filepath,"");
	strcat(filepath,"CS_Data/");
	strcat(filepath,ID);

	user_data_file = fopen(filepath,"wb+");
	fwrite(auth_send_msg->message,sizeof(unsigned char),auth_send_msg->msg_len,user_data_file);
	fclose(user_data_file);

	mbedtls_printf("\tWrtie (Ci,Di,Ei,h(y)) to Control Center user database.\n");
	mbedtls_printf("\tnote: this program use MD5 Hash function, so do not save Hash function.\n");
	mbedtls_printf("\tWrtie to path %s\n",filepath);
	mbedtls_printf("\tUser registion complete.\n");
	return 0;
}

int authent_server_user(mbedtls_ctr_drbg_context *ctr_drbg,auth_proto_msg *auth_rece_msg){

	char buff[1024];
	unsigned int buff_len = 0;

	int ret;

	auth_proto_msg auth_send_msg;

	int server_sockfd;
	struct sockaddr_in server_address;
	int server_port = 9737;

	unsigned char tmp_cmput[128];
	unsigned int cmput_len = 0;
	unsigned char tmp_digest[16];
	unsigned char tmp_xor[16];

	unsigned char digest_F[16];
	unsigned char digest_G[16];
	unsigned char digest_Pij[16];
	unsigned char digest_CID[16];
	unsigned char digest_SID[16];
	unsigned char digest_K[16];
	unsigned char digest_M[16];
	unsigned char rng_Ni2[16];
	unsigned char digest_Mi[16];
	unsigned char rng_Ni1[16];
	unsigned char digest_B[16];
	unsigned char digest_A[16];
	unsigned char digest_Gi[16];
	unsigned char digest_Q[16];
	unsigned char digest_R[16];
	unsigned char digest_V[16];
	unsigned char digest_T[16];
	unsigned char SK[16];

	/************从消息中提取提取Fi,Gi,Pij,CID,SID,Ki,M,********************/
	buff_len = 0;
	memcpy( digest_F, auth_rece_msg->message+buff_len, sizeof(digest_F) );
	buff_len += sizeof(digest_F);
	memcpy( digest_G, auth_rece_msg->message+buff_len, sizeof(digest_G) );
	buff_len += sizeof(digest_G);
	memcpy( digest_Pij, auth_rece_msg->message+buff_len, sizeof(digest_Pij));
	buff_len += sizeof(digest_Pij);
	memcpy( digest_CID, auth_rece_msg->message+buff_len, sizeof(digest_CID));
	buff_len += sizeof(digest_CID);
	memcpy( digest_SID, auth_rece_msg->message+buff_len, sizeof(digest_SID));
	buff_len += sizeof(digest_SID);
	memcpy( digest_K, auth_rece_msg->message+buff_len, sizeof(digest_K));
	buff_len += sizeof(digest_K);
	memcpy( digest_M, auth_rece_msg->message+buff_len, sizeof(digest_M));
	buff_len += sizeof(digest_M);
	/***********************************************************************/
	mbedtls_printf("STEP2: Exchang Key Phase\n");
	mbedtls_printf("\tthe receive digest_F   = ");
	print_128bits(digest_F);
	mbedtls_printf("\tthe receive digest_G   = ");
	print_128bits(digest_G);
	mbedtls_printf("\tthe receive digest_Pij = ");
	print_128bits(digest_Pij);
	mbedtls_printf("\tthe receive digest_CID = ");
	print_128bits(digest_CID);
	mbedtls_printf("\tthe receive digest_SID = ");
	print_128bits(digest_SID);
	mbedtls_printf("\tthe receive digest_K   = ");
	print_128bits(digest_K);
	mbedtls_printf("\tthe receive digest_M   = ");
	print_128bits(digest_M);

	/*********************************计算Ni2*******************************/
	XOR_128bits( digest_K, digest_SID_y, rng_Ni2 );
	/***********************************************************************/

	/*********************************计算M'*******************************/
	memset( tmp_cmput, 0, sizeof(tmp_cmput) );
	cmput_len = 0;
	memcpy( tmp_cmput + cmput_len, digest_x_y, sizeof(digest_x_y));
	cmput_len += sizeof(digest_x_y);
	memcpy( tmp_cmput + cmput_len, rng_Ni2, sizeof(rng_Ni2));
	cmput_len += sizeof(rng_Ni2);
	mbedtls_md5( tmp_cmput, cmput_len, tmp_digest);
	mbedtls_md5( tmp_digest, sizeof(tmp_digest), digest_Mi);
	/**********************************************************************/

	mbedtls_printf("\tthe digest_SID_y       = ");
	print_128bits(digest_SID_y);
	mbedtls_printf("\tthe compute rng_Ni2    = ");
	print_128bits(rng_Ni2);
	mbedtls_printf("\tthe compute digest_Mi  = ");
	print_128bits(digest_Mi);

	ret = memcmp( digest_M, digest_Mi, sizeof(digest_M));
	if( 0 == ret){
		mbedtls_printf("\tServer Authenticated by contro-center. M = M'.\n");
		/*******************************计算Ni1****************************/
		XOR_128bits(digest_F,digest_y,rng_Ni1);
 
		/******************************计算Bi******************************/
		memset( tmp_cmput, 0, sizeof(tmp_cmput));
		cmput_len = 0;
		memcpy( tmp_cmput + cmput_len, digest_y, sizeof(digest_y));
		cmput_len += sizeof(digest_y);
		memcpy( tmp_cmput + cmput_len, rng_Ni1, sizeof(rng_Ni1));
		cmput_len += sizeof(rng_Ni1);
		memcpy( tmp_cmput + cmput_len, digest_SID, sizeof(digest_SID));
		cmput_len += sizeof(digest_SID);
		mbedtls_md5( tmp_cmput, cmput_len,tmp_digest);
		XOR_128bits( tmp_digest, digest_Pij, tmp_xor);
		XOR_128bits( tmp_xor, digest_x_y, digest_B);
		/******************************************************************/

		/***********************计算Ai*************************************/
		memset( tmp_cmput, 0, sizeof(tmp_cmput));
		cmput_len = 0;
		memcpy( tmp_cmput + cmput_len, digest_B, sizeof(digest_B));
		cmput_len += sizeof(digest_B);
		memcpy( tmp_cmput + cmput_len, digest_F, sizeof(digest_F));
		cmput_len += sizeof(digest_F);
		memcpy( tmp_cmput + cmput_len, rng_Ni1, sizeof(rng_Ni1));
		cmput_len += sizeof(rng_Ni1);
		mbedtls_md5(tmp_cmput, cmput_len, tmp_xor);
		XOR_128bits(tmp_xor,digest_CID,digest_A);
		/******************************************************************/

		/***********************计算Gi*************************************/
		memset( tmp_cmput, 0, sizeof(tmp_cmput));
		cmput_len = 0;
		memcpy( tmp_cmput + cmput_len, digest_B, sizeof(digest_B));
		cmput_len += sizeof(digest_B);
		memcpy( tmp_cmput + cmput_len, digest_A, sizeof(digest_A));
		cmput_len += sizeof(digest_A);
		memcpy( tmp_cmput + cmput_len, rng_Ni1, sizeof(rng_Ni1));
		cmput_len += sizeof(rng_Ni1);
		mbedtls_md5( tmp_cmput, cmput_len, digest_Gi);
		/******************************************************************/
		mbedtls_printf("STEP3: Exchang Key Phase\n");
		mbedtls_printf("\tthe save digest_y =  ");
		print_128bits(digest_y);
		mbedtls_printf("\tthe save digest_A =  ");
		print_128bits(digest_A);
		mbedtls_printf("\tthe computed rng_Ni1  = ");
		print_128bits(rng_Ni1);
		mbedtls_printf("\tthe computed digest_B = ");
		print_128bits(digest_B);
		mbedtls_printf("\tthe computed digest_Gi = ");
		print_128bits(digest_Gi);

		/*****************比较G 是否等于 G' *******************************/
		ret = memcmp( digest_G, digest_Gi, sizeof(digest_G));
		if( 0 == ret){
			mbedtls_printf("\tUser Authenticated by control-center. G = G'.\n");
			/***********************产生随机数Ni3**************************/
			mbedtls_ctr_drbg_random( ctr_drbg, rng_Ni3, sizeof(rng_Ni3) );

			mbedtls_printf("STEP4: Exchang Key Phase\n");
			mbedtls_printf("\tgenerat rng_Ni3        = ");
			print_128bits(rng_Ni3);

			/******************************计算Qi********************************/
			memset( tmp_cmput, 0, sizeof(tmp_cmput) );
			cmput_len = 0;
			memcpy( tmp_cmput + cmput_len, digest_SID, sizeof(digest_SID));
			cmput_len += sizeof(digest_SID);
			memcpy( tmp_cmput + cmput_len, rng_Ni2, sizeof(rng_Ni2));
			cmput_len += sizeof(rng_Ni2);
			mbedtls_md5( tmp_cmput, cmput_len, tmp_digest);
			XOR_128bits( tmp_digest, rng_Ni1, tmp_xor);
			XOR_128bits( tmp_xor, rng_Ni3, digest_Q);

			/******************************计算Ri********************************/
			memset( tmp_cmput, 0, sizeof(tmp_cmput) );
			cmput_len = 0;
			memcpy( tmp_cmput + cmput_len, digest_A, sizeof(digest_A));
			cmput_len += sizeof(digest_A);
			memcpy( tmp_cmput + cmput_len, digest_B, sizeof(digest_B));
			cmput_len += sizeof(digest_B);
			mbedtls_md5( tmp_cmput, cmput_len, tmp_digest);

			XOR_128bits( rng_Ni1, rng_Ni2, tmp_xor);
			XOR_128bits( tmp_xor, rng_Ni3, digest_Mi);
			mbedtls_md5( digest_Mi, sizeof(digest_Mi),tmp_xor);

			XOR_128bits( tmp_digest, tmp_xor, digest_R);

			/******************************计算Vi********************************/
			memset( tmp_cmput, 0, sizeof(tmp_cmput));
			cmput_len = 0;
			memcpy( tmp_cmput + cmput_len, tmp_digest, sizeof(tmp_digest) );
			cmput_len += sizeof(tmp_digest);
			memcpy( tmp_cmput + cmput_len, tmp_xor, sizeof(tmp_xor));
			cmput_len += sizeof(tmp_xor);
			mbedtls_md5( tmp_cmput, cmput_len, digest_V);

			/******************************计算Ti********************************/
			memset( tmp_cmput, 0, sizeof(tmp_cmput));
			cmput_len = 0;
			memcpy( tmp_cmput + cmput_len, digest_A, sizeof(digest_A));
			cmput_len += sizeof(digest_A);
			memcpy( tmp_cmput + cmput_len, digest_B, sizeof(digest_B));
			cmput_len += sizeof(digest_B);
			memcpy( tmp_cmput + cmput_len, rng_Ni1, sizeof(rng_Ni1));
			cmput_len += sizeof(rng_Ni1);
			mbedtls_md5( tmp_cmput, cmput_len, tmp_digest);
			XOR_128bits( tmp_digest, rng_Ni2, tmp_xor);
			XOR_128bits( tmp_xor, rng_Ni3, digest_T);

			
			/*****************************计算最终SK******************************/
			memset( tmp_cmput, 0, sizeof(tmp_cmput));
			cmput_len = 0;
			memcpy( tmp_cmput + cmput_len, digest_A, sizeof(digest_A));
			cmput_len += sizeof(digest_A);
			memcpy( tmp_cmput+ cmput_len, digest_B,sizeof(digest_B));
			cmput_len += sizeof(digest_B);
			mbedtls_md5( tmp_cmput, cmput_len, tmp_digest);

			XOR_128bits( rng_Ni1, rng_Ni2, digest_Gi);
			XOR_128bits( digest_Gi, rng_Ni3, tmp_xor);

			memset( tmp_cmput, 0, sizeof(tmp_cmput));
			cmput_len = 0;
			memcpy( tmp_cmput + cmput_len, tmp_digest, sizeof(tmp_digest) );
			cmput_len += sizeof(tmp_digest);
			memcpy( tmp_cmput + cmput_len, tmp_xor, sizeof(tmp_xor)); 
			cmput_len += sizeof(tmp_xor);
			mbedtls_md5(tmp_cmput, cmput_len, SK);

			/******************************Ni1 or Ni3*****************************/
			XOR_128bits( rng_Ni1, rng_Ni3, tmp_digest);
			XOR_128bits( rng_Ni2, rng_Ni3, tmp_xor);

			mbedtls_printf("\tthe rng_Ni1 or rng_Ni3 = ");
			print_128bits(tmp_digest);
			mbedtls_printf("\tthe rng_Ni2 or rng_Ni3 = ");
			print_128bits(tmp_xor);
			mbedtls_printf("\tthe sent digest_Q      = ");
			print_128bits(digest_Q);
			mbedtls_printf("\tthe sent digest_R      = ");
			print_128bits(digest_R);
			mbedtls_printf("\tthe sent digest_V      = ");
			print_128bits(digest_V);
			mbedtls_printf("\tthe sent digest_T      = ");
			print_128bits(digest_T);
			mbedtls_printf("\tthe Final Exchange-Key = ");
			print_128bits(SK);

			/***********************构造发送数据**********************************/
			memset(buff, 0, sizeof(buff));
			buff_len = 0;
			memcpy(buff + buff_len, digest_Q, sizeof(digest_Q));
			buff_len += sizeof(digest_Q);
			memcpy(buff + buff_len, digest_R, sizeof(digest_R));
			buff_len += sizeof(digest_R);
			memcpy(buff + buff_len, digest_V, sizeof(digest_V));
			buff_len += sizeof(digest_V);
			memcpy(buff + buff_len, digest_T, sizeof(digest_T));
			buff_len += sizeof(digest_T);

			auth_send_msg.phase = AUTH_PROTO_PHASE_EXHANGEKEY;
			memcpy( auth_send_msg.message, buff, buff_len );
			auth_send_msg.msg_len = buff_len;

			memset(buff, 0, sizeof(buff));
			buff_len = 0;
			memcpy(buff, &auth_send_msg, sizeof(auth_proto_msg));
			buff_len += sizeof(auth_proto_msg);

			server_sockfd = socket( AF_INET, SOCK_STREAM, 0 );
			server_address.sin_family = AF_INET;
			server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
			server_address.sin_port = htons(server_port);
			//连接服务提供者
			ret = connect( server_sockfd, (struct sockaddr *)&server_address, sizeof(server_address) );
			if( -1 == ret ){
				mbedtls_printf(" error in send (Qi,Ri,Vi,Ti): can't connect the server.\n");
				return -1;
			}else{
				ret = write( server_sockfd, buff, buff_len);
				if( -1 == ret ){
					mbedtls_printf("error in send (Qi,Ri,Vi,Ti): failed to write message to server_sock.\n");
				}else{
					mbedtls_printf("\tsent the Authenticated message (Qi,Ri,Vi,Ti) to Server.\n");
					close(server_sockfd);
				}
			}
		}else{
			mbedtls_printf( "digest_G is not euqal to digest_Gi: G != G'.\n" );
			mbedtls_printf( "User not authenticated by control center.\n" );
			return -1;
		}
	}else{
		mbedtls_printf( "digest_M is not euqal to digest_Mi: M != M'.\n" );
		mbedtls_printf( "Server not authenticated by control center.\n" );
		return -1;
	}
	return 0;
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

	int control_center_socketfd = -1;
	int client_socketfd = -1;
	unsigned int client_len = 0;
	struct sockaddr_in control_center_addr;
	struct sockaddr_in cliern_addr;

	int ret;

	char send_buff[1024];
	int send_len = 0;
	
	auth_proto_msg receive_auth_message,send_auth_message;

	/*****************************创建控制中心流式套接字***************************/
	control_center_socketfd = socket(AF_INET,SOCK_STREAM,0);

	/********************设置控制中心接收连接地址和监听端口************************/
	control_center_addr.sin_family = AF_INET; //使用IPv4协议            
	control_center_addr.sin_addr.s_addr = htonl(INADDR_ANY); //接受来自任何地址的请求
	control_center_addr.sin_port = htons(CS_PORT);	//开放的服务端口号

	//绑定套接字
	bind(control_center_socketfd,(struct sockaddr *)&control_center_addr,sizeof(control_center_addr));
	listen(control_center_socketfd,15);

	random_nunber_init( &ctr_drbg , &entropy );
	send_sharemessage_to_server();
	while(1){
	
		client_len = sizeof(cliern_addr);
		mbedtls_fprintf(stderr, "Control Center is listening ...\n");
		client_socketfd = accept( control_center_socketfd, (struct sockaddr *)&cliern_addr, &client_len );
		if(0 == fork()){

			mbedtls_printf("receive a connection. \n");
			/*********子进程中读取发送过来的信息，处理信息，在发送给客户端*****************/
			memset( send_buff, 0, sizeof(send_buff) );
			ret = read(client_socketfd,(void *)send_buff,sizeof(send_buff));
			if( -1 == ret ){
				mbedtls_printf("error in sock read message.\n");
				exit(0);
			}
			memset( &receive_auth_message, 0, sizeof(receive_auth_message));
			memcpy( &receive_auth_message, send_buff, sizeof(receive_auth_message));
			/*******************************************************************************/

			if( AUTH_PROTO_PHASE_REGISTION == receive_auth_message.phase){
				registion_for_user(&receive_auth_message,&send_auth_message);
				memset(send_buff,0,sizeof(send_buff));
				send_len += sizeof(auth_proto_msg);
				memcpy(send_buff,&send_auth_message,send_len);
				/**************************************************************************/
				ret = write(client_socketfd,(void *)send_buff,send_len);
				if( -1 == ret){
					mbedtls_printf("error int sock write (Ci,Di,Ei,h(y)).\n");
					exit(0);
				}
				/***************************************************************************/
			}else if(AUTH_PROTO_PHASE_LOGIN == receive_auth_message.phase){
				
			}else if(AUTH_PROTO_PHASE_EXHANGEKEY == receive_auth_message.phase){
				authent_server_user(&ctr_drbg,&receive_auth_message);
			}else{
				mbedtls_printf("auth process phase error.\n");
				mbedtls_printf("Plese check the receice message.\n");
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
