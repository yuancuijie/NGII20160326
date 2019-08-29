
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

void checkHash(void){
	int i ;
	unsigned char str[] = "hello world";
	unsigned char digest[16];

	mbedtls_printf("\n MD5(%s) =",str);
	mbedtls_md5((unsigned char *)str, sizeof(str)-1, digest);

	for(i = 0 ; i < 16 ; i++){
		mbedtls_printf("%02x", digest[i]);
	}
	mbedtls_printf( "\n\n" );
	fflush( stdout );
}

int checkRandom(){
	int ret;
	unsigned int i;
	mbedtls_ctr_drbg_context ctr_drbg;
	mbedtls_entropy_context entropy;

	unsigned char buff[16];

	/*CTR_DRBG context initialization Makes the context ready for mbedtls_ctr_drbg_seed() or mbedtls_ctr_drbg_free()*/
	mbedtls_ctr_drbg_init( &ctr_drbg );

	/************Initialize the context***********/
	mbedtls_entropy_init( &entropy );

	/**CTR_DRBG initial seeding Seed and setup entropy source for future reseeds.（生成随机数种子）详情见mbedtls帮助文档
	* "RANDOM_GEN" 为个性化数据，添加这个参数使得种子生成更加独特                                                   */
	ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *) "RANDOM_GEN",sizeof("RANDOM_GEN") );
	if( 0 != ret ){
		mbedtls_printf( "failed in mbedtls_ctr_drbg_seed : ret = %d\n", ret);
		mbedtls_printf( "failed in random number general seed.\n" );
		return -1;
	}

	/*Enable / disable prediction resistance 设置随机数抗预测*/
	mbedtls_ctr_drbg_set_prediction_resistance( &ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );

	/*generate a 128 bit num*/
	ret = mbedtls_ctr_drbg_random( &ctr_drbg, buff, sizeof(buff) );
	if(0 != ret ){
		mbedtls_printf( "failed in generating 128 bit num.\n" );
		return -1;
	}

	mbedtls_printf("The random number is ");
	for (i = 0; i < sizeof(buff); ++i){
		mbedtls_printf( "%02x", buff[i]);
	}
	mbedtls_printf("\n");

	return 0;
}

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

void print_start_information(void){
	mbedtls_printf("\n\n\n");
	mbedtls_printf("\t\t**********user authentication control************\n");
	mbedtls_printf("\t\t***                                           ***\n");
	mbedtls_printf("\t\t***     1.user registion                      ***\n");
	mbedtls_printf("\t\t***     2.user login                          ***\n");
	mbedtls_printf("\t\t***     3.help                                ***\n");
	mbedtls_printf("\t\t***     0.exit                                ***\n");
	mbedtls_printf("\t\t***                                           ***\n");
	mbedtls_printf("\t\t*************************************************\n");
	mbedtls_printf("\t\tinput the number chose fuction, press the ENTER do it\n####");
}

int regist_for_CS(mbedtls_ctr_drbg_context *ctr_drbg){
	int cs_sockfd,ret;
	int csport = 9736;
	struct sockaddr_in cs_address;
	char input_flag = 0;

	int hash_length = 0;
	int send_length = 0;
	char send_buff[1024];

	char ID[16];
	char PW[16];
	char PW2[16];
	unsigned char rng_b[16];
	unsigned char tmp_cmput[100];
	unsigned char digest_A[16];

	unsigned char sub_digest[5][16];
	auth_proto_msg auth_msg;

	FILE *user_datafile;
	char smartCard_path[128];


	//Step1:用户输入用户名口令
	do{
		mbedtls_printf("please input the ID you want.the ID must less than 15 chars\n####");
		ret = scanf("%s",ID);
		if(!ret) {
			mbedtls_printf("scanf input error in input ID\n");
			exit(0);
		}
		mbedtls_printf("please input the password .\n####");
		ret = scanf("%s",PW);
		if(!ret) {
			mbedtls_printf("scanf input error,in input PW\n");
			exit(0);
		}
		mbedtls_printf("please input the password again.\n####");
		ret = scanf("%s",PW2);
		if(!ret) {
			mbedtls_printf("scanf input error,in input PW 2\n");
			exit(0);
		}

		if( !strcmp( PW, PW2 ) ){
			input_flag = 1;
		}else{
			mbedtls_printf("password is different between PW and PW2!\n");
			input_flag = 0;
		}
	}while( !input_flag );
	
	mbedtls_printf("password input correctly.\n####");
	mbedtls_printf("STEP1: User Registion Phase\n");

	//智能卡产生随机数b
	mbedtls_ctr_drbg_random( ctr_drbg, rng_b, sizeof(rng_b) );

	/*************************计算Ai************************************************/
	memset( tmp_cmput, 0, sizeof(tmp_cmput) );
	hash_length = 0;
	memcpy( tmp_cmput+hash_length, rng_b, sizeof(rng_b));
	hash_length += sizeof(rng_b);
	memcpy(tmp_cmput+hash_length ,PW, strlen(PW));
	hash_length += strlen(PW);
	mbedtls_md5(tmp_cmput, hash_length, digest_A);
	/********************************************************************************/

	mbedtls_printf("\tthe comput digest_A = ");
	print_128bits(digest_A);

	//构造发送数据
	memset(send_buff,0,sizeof(send_buff));
	memcpy(send_buff,digest_A,sizeof(digest_A));
	send_length += sizeof(digest_A);
	memcpy( send_buff+send_length, ID, sizeof(ID) );
	send_length += sizeof(ID);
	
	auth_msg.phase = AUTH_PROTO_PHASE_REGISTION;
	memcpy(auth_msg.message,send_buff,send_length);
	auth_msg.msg_len = send_length;

	memset( send_buff, 0, sizeof(send_buff) );
	send_length = 0;
	memcpy( send_buff, &auth_msg, sizeof(auth_msg));
	send_length += sizeof(auth_msg);

	//创建套接字准备发送
	cs_sockfd = socket( AF_INET, SOCK_STREAM,0);
	cs_address.sin_family = AF_INET;
	cs_address.sin_addr.s_addr = inet_addr("127.0.0.1");
	cs_address.sin_port = htons(csport);
	//连接控制中心
	ret = connect( cs_sockfd, (struct sockaddr *)&cs_address, sizeof(cs_address) );
	if(-1 == ret){
		mbedtls_fprintf(stderr, "can't connect Control Center\n");	
		return -1;
	}else{
		//发送数据给服务器
		ret = write( cs_sockfd, send_buff, send_length);
		if(-1 == ret){
			mbedtls_printf("error in wirte functions while sending (Ai||PW).\n");
			return -1;
		}
		mbedtls_printf("\tsent (Ai,Pw) to Control Center.\n\n");

		memset(send_buff,0,sizeof(send_buff));

		mbedtls_printf("STEP3: User Registion Phase.\n");

		ret = read( cs_sockfd, send_buff, send_length);
		memset(&auth_msg,0,sizeof(auth_msg));
		memcpy(&auth_msg,send_buff,sizeof(auth_msg));
		split_message(auth_msg.message,auth_msg.msg_len/16,sub_digest);
		
		strcpy(smartCard_path,"");
		strcat(smartCard_path,"User_SmartCard/");
		strcat(smartCard_path,ID);

		user_datafile = fopen(smartCard_path,"wb+");

		memset(send_buff,0,sizeof(send_buff));
		send_length = 0;
		memcpy(send_buff,auth_msg.message,auth_msg.msg_len);
		send_length += auth_msg.msg_len;
		memcpy(send_buff+send_length,rng_b,sizeof(rng_b));
		send_length += sizeof(rng_b);
		fwrite(send_buff,sizeof(unsigned char),send_length,user_datafile);
		fclose(user_datafile);
		close( cs_sockfd );

		mbedtls_printf("\t smartCard Save (Ci,Di,Ei,h(y),rng_b).\n");
		mbedtls_printf("\tnote: this program use MD5 Hash function, so do not save Hash function.\n\n");
		return 0;
	}
	return 0;
}


unsigned char rng_Ni1[16];

int login_for_CS(mbedtls_ctr_drbg_context *ctr_drbg){
	int server_sockfd,ret;
	int server_port = 9737;
	struct sockaddr_in server_address;

	int smartCard_sockfd;
	struct sockaddr_in smartCard_address;
	int smartCard_port = 9738;

	int client_sockfd;
	struct sockaddr_in client_address;
	unsigned int client_len;

	char ID[16];
	char PW[16];
	char ServID[30];

	char filePath[128];
	FILE *user_datafile;

	char buff[1024];
	int buff_length = 0;

	unsigned char digest_Ci[16];

	unsigned char digest_A[16];
	unsigned char digest_B[16];
	unsigned char digest_C[16];
	unsigned char digest_D[16];
	unsigned char digest_y[16];
	unsigned char digest_E[16];
	unsigned char digest_F[16];
	unsigned char digest_Pij[16];
	unsigned char digest_CID[16];
	unsigned char digest_G[16];
	unsigned char digest_SID[16];
	unsigned char rng_b[16];
	unsigned char digest_V[16];
	unsigned char digest_T[16];
	unsigned char digest_Vi[16];
	unsigned char Ni2_xor_Ni3[16];
	unsigned char SK[16];


	unsigned char tmp_cmput[128];
	int cmput_length = 0;
	unsigned char tmp_xor[16];
	unsigned char tmp_digest[16];

	auth_proto_msg send_auth_msg;

	/****************************************提示用户输入ID，PW，SID*************************/
	mbedtls_printf("please input registed ID you.\n####");
	ret = scanf("%s",ID);
	if(!ret) {
		mbedtls_printf("scanf input error in input ID\n");
		exit(0);
	}
	mbedtls_printf("please input the password .\n####");
	ret = scanf("%s",PW);
	if(!ret) {
		mbedtls_printf("scanf input error,in input PW\n");
		exit(0);
	}
	mbedtls_printf("please input the server IP and port. Eg: 192.168.0.1:8592 \n####");
	ret = scanf("%s",ServID);
	if(!ret) {
		mbedtls_printf("scanf input error,in input ServID\n");
		exit(0);
	}
	/******************************************************************************************/

	/******************************查询用户是否注册过******************************************/
	ret = findFileList("User_SmartCard",ID);
	if( -1 == ret){
		mbedtls_printf("the user ID %s do not regist for Control Center,please regist for CS\n",ID);
		return -1;
	}else{
		mbedtls_printf("find ID %s.\n",ID);
		/***********************读取用户文件提取Ci，Di，Ei，h(y),rng_b************************/
		memset(filePath,0,sizeof(filePath));
		strcat(filePath,"");
		strcat(filePath,"User_SmartCard/");
		strcat(filePath,ID);
		mbedtls_printf("%s\n",filePath);
		user_datafile = fopen(filePath,"rb+");
		ret = fread(buff,sizeof(unsigned char),5*16,user_datafile);
		fclose(user_datafile);
		if( 5*16 != ret){
			mbedtls_printf("error in read user_datafile.\n");
			exit(0);
		}else{
			memcpy(digest_C, buff + buff_length, sizeof(digest_C));
			buff_length += sizeof(digest_C);
			memcpy(digest_D, buff + buff_length, sizeof(digest_D));
			buff_length += sizeof(digest_D);
			memcpy(digest_E, buff + buff_length, sizeof(digest_E));
			buff_length += sizeof(digest_E);
			memcpy(digest_y, buff + buff_length, sizeof(digest_y));
			buff_length += sizeof(digest_y);
			memcpy(rng_b, buff + buff_length, sizeof(rng_b));


			mbedtls_printf("STEP1: User Login Phase\n");
			mbedtls_printf("\tFrom the user file read the digest message\n");
			mbedtls_printf("\tthe read digest_C = ");
			print_128bits(digest_C);
			mbedtls_printf("\tthe read digest_D = ");
			print_128bits(digest_D);
			mbedtls_printf("\tthe read digest_E = ");
			print_128bits(digest_E);
			mbedtls_printf("\tthe read digest_y = ");
			print_128bits(digest_y);
			mbedtls_printf("\tthe general rng_b = ");
			print_128bits(rng_b);
		}
		/*****************************************************************************************/

		/*******************************计算Ai*****************************************************/
		memset(tmp_cmput, 0 ,sizeof(tmp_cmput));
		cmput_length = 0;
		memcpy(tmp_cmput+ cmput_length,rng_b,sizeof(rng_b));
		cmput_length += sizeof(rng_b);
		memcpy(tmp_cmput+ cmput_length,PW,strlen(PW));
		cmput_length += strlen(PW);
		mbedtls_md5(tmp_cmput, cmput_length, digest_A);
		/******************************************************************************************/

		/*******************************计算SID*****************************************************/
		mbedtls_md5((unsigned char *)ServID, strlen(ServID), digest_SID);

		/******************************   计算Ci' **************************************************/
		memset(tmp_cmput, 0, sizeof(tmp_cmput));
		cmput_length = 0;
		memcpy(tmp_cmput + cmput_length, ID, strlen(ID));
		cmput_length += strlen(ID);
		memcpy(tmp_cmput + cmput_length, digest_y, sizeof(digest_y));
		cmput_length += sizeof(digest_y);
		memcpy(tmp_cmput + cmput_length, digest_A, sizeof(digest_A));
		cmput_length +=sizeof(digest_A);
		mbedtls_md5(tmp_cmput, cmput_length, digest_Ci);
		/******************************************************************************************/

		mbedtls_printf("\tthe comput digest_A  = ");
		print_128bits(digest_A);
		mbedtls_printf("\tthe comput digest_Ci = ");
		print_128bits(digest_Ci);
		mbedtls_printf("\n");

		ret = memcmp(digest_Ci,digest_C,sizeof(digest_Ci));
		if( 0 != ret){
			mbedtls_printf("User is illegal ,authentication terminated.\n");
			return -1;
		}else{
			mbedtls_printf("\tUser is legal. Ci = Ci'\n");

			//产生随机数Ni1
			mbedtls_ctr_drbg_random( ctr_drbg, rng_Ni1, sizeof(rng_Ni1) );

			user_datafile = fopen("User_SmartCard/tmpFile","wb+");
			fwrite( rng_Ni1, sizeof(unsigned char), sizeof(rng_Ni1), user_datafile);
			fclose( user_datafile );

			/****************************计算Bi****************************************************/
			memset(tmp_cmput, 0, sizeof(tmp_cmput));
			cmput_length = 0;
			memcpy(tmp_cmput + cmput_length, ID, strlen(ID));
			cmput_length += strlen(ID);
			memcpy(tmp_cmput + cmput_length, digest_A, sizeof(digest_A));
			cmput_length += sizeof(digest_A);
			mbedtls_md5(tmp_cmput, cmput_length, tmp_xor);
			XOR_128bits(tmp_xor, digest_D, digest_B);
			/**************************************************************************************/

			/****************************计算Fi****************************************************/
			memcpy(tmp_xor, digest_y, sizeof(digest_y));
			XOR_128bits(tmp_xor, rng_Ni1, digest_F);
			/**************************************************************************************/

			/****************************计算Pij****************************************************/
			memset(tmp_cmput, 0, sizeof(tmp_cmput));
			cmput_length = 0;
			memcpy(tmp_cmput + cmput_length, digest_y, sizeof(digest_y));
			cmput_length += sizeof(digest_y);
			memcpy(tmp_cmput + cmput_length, rng_Ni1, sizeof(rng_Ni1));
			cmput_length += sizeof(rng_Ni1);
			memcpy(tmp_cmput + cmput_length, digest_SID, sizeof(digest_SID));
			cmput_length += sizeof(digest_SID);
			mbedtls_md5(tmp_cmput,cmput_length,tmp_xor);
			XOR_128bits(tmp_xor, digest_E, digest_Pij);
			/****************************************************************************************/

			/****************************计算CID*****************************************************/
			memset(tmp_cmput, 0 ,sizeof(tmp_cmput));
			cmput_length = 0;
			memcpy(tmp_cmput + cmput_length,digest_B,sizeof(digest_B));
			cmput_length += sizeof(digest_B);
			memcpy(tmp_cmput + cmput_length,digest_F,sizeof(digest_F));
			cmput_length += sizeof(digest_F);
			memcpy(tmp_cmput + cmput_length,rng_Ni1,sizeof(rng_Ni1));
			cmput_length += sizeof(rng_Ni1);
			mbedtls_md5(tmp_cmput,cmput_length,tmp_xor);
			XOR_128bits(tmp_xor,digest_A,digest_CID);
			/****************************************************************************************/

			/****************************计算Gi*****************************************************/
			memset(tmp_cmput, 0, sizeof(tmp_cmput));
			cmput_length = 0;
			memcpy(tmp_cmput + cmput_length,digest_B,sizeof(digest_B));
			cmput_length += sizeof(digest_B);
			memcpy(tmp_cmput + cmput_length,digest_A,sizeof(digest_A));
			cmput_length += sizeof(digest_A);
			memcpy(tmp_cmput + cmput_length,rng_Ni1,sizeof(rng_Ni1));
			cmput_length += sizeof(rng_Ni1);
			mbedtls_md5(tmp_cmput,cmput_length,digest_G);
			/****************************************************************************************/

			mbedtls_printf("STEP2: User Login\n");
			mbedtls_printf("\tthe comput digest_SID = ");
			print_128bits(digest_SID);
			mbedtls_printf("\tthe generat rng_Ni1   = ");
			print_128bits(rng_Ni1);
			mbedtls_printf("\tthe send digest_B     = ");
			print_128bits(digest_B);
			mbedtls_printf("\tthe send digest_F     = ");
			print_128bits(digest_F);
			mbedtls_printf("\tthe send digest_Pij   = ");
			print_128bits(digest_Pij);
			mbedtls_printf("\tthe send digest_CID   = ");
			print_128bits(digest_CID);
			mbedtls_printf("\tthe send digest_G     = ");
			print_128bits(digest_G);

			/*********************************构造发送数据*******************************************/
			memset(buff, 0, sizeof(buff));
			buff_length = 0;
			memcpy(buff+buff_length,digest_F,sizeof(digest_F));
			buff_length += sizeof(digest_F);
			memcpy(buff+buff_length,digest_G,sizeof(digest_G));
			buff_length += sizeof(digest_G);
			memcpy(buff+buff_length,digest_Pij,sizeof(digest_Pij));
			buff_length += sizeof(digest_Pij);
			memcpy(buff+buff_length,digest_CID,sizeof(digest_CID));
			buff_length +=sizeof(digest_CID);

			memset(&send_auth_msg, 0, sizeof(auth_proto_msg));
			send_auth_msg.phase = AUTH_PROTO_PHASE_LOGIN;
			memcpy(send_auth_msg.message,buff,buff_length);
			send_auth_msg.msg_len = buff_length;

			memset(buff, 0, sizeof(buff));
			buff_length = 0;
			memcpy(buff, &send_auth_msg, sizeof(auth_proto_msg));
			buff_length += sizeof(auth_proto_msg);
			/*******************************************************************************************/

			//创建套接字准备发送
			server_sockfd = socket( AF_INET, SOCK_STREAM,0);
			server_address.sin_family = AF_INET;
			server_address.sin_addr.s_addr = inet_addr("127.0.0.1");
			server_address.sin_port = htons(server_port);
			//连接服务提供者
			ret = connect( server_sockfd, (struct sockaddr *)&server_address, sizeof(server_address) );
			if( -1 == ret){
				mbedtls_printf("connect server error.\n");
				return -1;
			}else{
				/***************************发送数据给服务提供者*****************************/
				ret = write( server_sockfd, buff, buff_length);
				if( -1 == ret){
					mbedtls_printf("error in writing (Fi,Gi,Pij,CIDj) to server.\n");
					return -1;
				}else{
					mbedtls_printf("\tSended message (Fi,Gi,Pij,CIDj) to server.\n\n");

					smartCard_sockfd = socket( AF_INET, SOCK_STREAM, 0 );
					smartCard_address.sin_family = AF_INET;
					smartCard_address.sin_addr.s_addr = htonl(INADDR_ANY);
					smartCard_address.sin_port = htons(smartCard_port);
					client_len = sizeof(client_address);
					bind(smartCard_sockfd,(struct sockaddr *)&smartCard_address,sizeof(smartCard_address));
					listen(smartCard_sockfd,2);
					client_sockfd = accept( smartCard_sockfd, (struct sockaddr *)&client_address, &client_len);

					memset( buff, 0, sizeof(buff) );
					ret = read( client_sockfd , buff, sizeof(buff) );
					if( -1 == ret ){
						mbedtls_printf("error in read (Vi,Ti) ");
						return -1;
					}else{
						memset( &send_auth_msg, 0, sizeof(auth_proto_msg));
						memcpy( &send_auth_msg, buff, sizeof(auth_proto_msg));
						if( AUTH_PROTO_PHASE_EXHANGEKEY == send_auth_msg.phase){
							memcpy( digest_V, send_auth_msg.message, sizeof(digest_V));
							memcpy( digest_T, send_auth_msg.message + sizeof(digest_V), sizeof(digest_V));

							mbedtls_printf("STEP6: Exchang Key Phase\n");
							mbedtls_printf("\tread from authentication message.\n");
							mbedtls_printf("\tthe read digest_V = ");
							print_128bits(digest_V);
							mbedtls_printf("\tthe read digest_T = ");
							print_128bits(digest_T);
							mbedtls_printf("\tthe rng_Ni1       = ");
							print_128bits(rng_Ni1);

							/****************************计算 Ni2 xor Ni3 *******************************/
							memset( tmp_cmput, 0, sizeof(tmp_cmput) );
							cmput_length = 0;
							memcpy( tmp_cmput + cmput_length, digest_A, sizeof(digest_A) );
							cmput_length += sizeof(digest_A);
							memcpy( tmp_cmput + cmput_length, digest_B, sizeof(digest_B) );
							cmput_length += sizeof(digest_B);
							memcpy( tmp_cmput + cmput_length, rng_Ni1, sizeof(rng_Ni1) );
							cmput_length += sizeof(rng_Ni1);
							mbedtls_md5( tmp_cmput, cmput_length, tmp_xor);
							XOR_128bits( tmp_xor, digest_T, Ni2_xor_Ni3);

							/*************************  计算 Vi' ******************************************/
							XOR_128bits( Ni2_xor_Ni3, rng_Ni1, tmp_digest);
							mbedtls_md5( tmp_digest, sizeof(tmp_digest), digest_Ci);

							memset( tmp_cmput, 0, sizeof(tmp_cmput) );
							cmput_length = 0;
							memcpy( tmp_cmput + cmput_length, digest_A, sizeof(digest_A) );
							cmput_length += sizeof(digest_A);
							memcpy( tmp_cmput + cmput_length, digest_B, sizeof(digest_B) );
							cmput_length += sizeof(digest_B);
							mbedtls_md5( tmp_cmput, cmput_length, tmp_xor);

							memset( tmp_cmput, 0, sizeof(tmp_cmput) );
							cmput_length = 0;
							memcpy( tmp_cmput + cmput_length, tmp_xor, sizeof(tmp_xor) );
							cmput_length += sizeof(tmp_xor);
							memcpy( tmp_cmput + cmput_length, digest_Ci,sizeof(digest_Ci) );
							cmput_length += sizeof(digest_Ci);
							mbedtls_md5( tmp_cmput, cmput_length, digest_Vi);

							mbedtls_printf("\tthe digest_A           = ");
							print_128bits(digest_A);
							mbedtls_printf("\tthe digest_B           = ");
							print_128bits(digest_B);
							mbedtls_printf("\tthe computed Ni2 or Ni3= ");
							print_128bits(Ni2_xor_Ni3);
							mbedtls_printf("\tthe computed digest_Vi = ");
							print_128bits(digest_Vi); 

							ret = memcmp( digest_Vi, digest_V, sizeof(digest_V) );
							if( 0 == ret ){
								mbedtls_printf("\tUser authenticated by the Server. Vi = Vi'\n");
								/************************计算最终SK***************************************/
								memset( tmp_cmput, 0, sizeof(tmp_cmput));
								cmput_length = 0;
								memcpy( tmp_cmput + cmput_length, digest_A, sizeof(digest_A));
								cmput_length += sizeof(digest_A);
								memcpy( tmp_cmput+ cmput_length, digest_B,sizeof(digest_B));
								cmput_length += sizeof(digest_B);
								mbedtls_md5( tmp_cmput, cmput_length, tmp_digest);

								XOR_128bits( Ni2_xor_Ni3, rng_Ni1, tmp_xor);

								memset( tmp_cmput, 0, sizeof(tmp_cmput));
								cmput_length = 0;
								memcpy( tmp_cmput + cmput_length, tmp_digest, sizeof(tmp_digest) );
								cmput_length += sizeof(tmp_digest);
								memcpy( tmp_cmput + cmput_length, tmp_xor, sizeof(tmp_xor)); 
								cmput_length += sizeof(tmp_xor);
								mbedtls_md5(tmp_cmput, cmput_length, SK);

								mbedtls_printf("\tthe Final Exchang-Key = ");
								print_128bits(SK);
							
								close(smartCard_sockfd);
								return 0;
							}else{
								mbedtls_printf("User not authenticated by the Server Vi != Vi'.\n");
								close(smartCard_sockfd);
								return -1;
							}
						}else{
							mbedtls_printf("error in authentication protocal phase.\n");
							close(smartCard_sockfd);
							return -1;
						}
					}
					close(server_sockfd);
				}
			}
		}		
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

	char cmd[10];
	int ret;

	/***************************初始化随机数环境************************/
	random_nunber_init( &ctr_drbg , &entropy );

	while(1){
		print_start_information();
		ret = scanf("%s",cmd);
		if(!ret){
			mbedtls_printf("input error in input main command.\n");
			exit(0);
		}
		if(!strcmp( cmd, "1" )){
			mbedtls_printf("press the 1.\n");	
			regist_for_CS(&ctr_drbg);
		}else if(!strcmp( cmd, "2" )){
			mbedtls_printf("press the 2.\n");
			login_for_CS(&ctr_drbg);
		}else if(!strcmp( cmd, "3" )){

			mbedtls_printf("press the 3.\n");

		}else if(!strcmp( cmd, "0" )){

			goto cleanup;
		}else{
			mbedtls_printf("input error,please input again.\n");
		} 
		fflush(stdin);
		mbedtls_printf("Press any key to return the main menu.\n");
		getchar();
		getchar();
	}
cleanup:
	mbedtls_printf("user logout..\n");
	return 0;
}
#endif
