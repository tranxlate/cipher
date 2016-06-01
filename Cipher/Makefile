#.SUFFIXES	: .c .cpp .o
SRC_DIR=src
INC_DIR=include
OBJ_DIR=obj
LIB_DIR=lib
TEST_DIR=test

#OpenSSL
SSL_DIR=/usr/local/ssl
SSL_INC_DIR=$(SSL_DIR)/include
SSL_LIB_DIR=$(SSL_DIR)/lib
SSL_LIB=ssl
CRYPTO_LIB=crypto

#Lib
CIPHER_LIB=Cipher

#make
all	: libdir cipher testpg

libdir	: 
	mkdir -p $(LIB_DIR)
	mkdir -p $(OBJ_DIR)
	
cipher	:
	g++ -c $(SRC_DIR)/Cipher.cpp -I$(INC_DIR) -I$(SSL_INC_DIR) -L$(SSL_LIB_DIR) -l$(CRYPTO_LIB) -l$(SSL_LIB) -ldl
	mv Cipher.o $(OBJ_DIR)
	ar rv $(LIB_DIR)/lib$(CIPHER_LIB).a $(OBJ_DIR)/Cipher.o

testpg	:
	g++ -o $(TEST_DIR)/CipherTest $(TEST_DIR)/CipherTest.cpp -I$(INC_DIR) -I$(SSL_INC_DIR) -L$(LIB_DIR) -L$(SSL_LIB_DIR) -l$(CIPHER_LIB) -l$(CRYPTO_LIB) -l$(SSL_LIB) -ldl

#.PHONY : clean	
clean	: 
	rm -rf $(OBJ_DIR)/*
	rm -rf $(LIB_DIR)/*