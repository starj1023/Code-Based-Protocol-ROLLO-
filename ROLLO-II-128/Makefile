CC=gcc
NO_RNG_WARNING:=-Wno-unused-but-set-variable -Wno-unused-parameter -Wno-sign-compare 
CFLAGS:=-O3 -flto -pedantic -Wall -Wextra ${NO_RNG_WARNING}

HASH_SRC:=lib/hash/hash.c
HASH_INCLUDE:=-I lib/hash -L/usr/local/Cellar//openssl/1.0.2r/lib -lcrypto

RNG_SRC:=lib/rng/nist-rng.c
RNG_INCLUDE:=-I lib/rng

FFI_SRC:=src/ffi
FFI_INCLUDE:=-I src/ffi

SRC:=src
INCLUDE:=-I src $(FFI_INCLUDE)
MAIN_ROLLO:=src/main_rollo.c
MAIN_KAT:=src/main_kat.c
LIB:=$(HASH_INCLUDE) $(RNG_INCLUDE)

ROLLO_OBJS:=ffi_elt.o ffi_vec.o ffi_poly.o ffi_vspace.o ffi_qre.o parsing.o rsr_algorithm.o kem.o 
ROLLO_OBJS_VERBOSE:=ffi_elt.o ffi_vec.o ffi_poly.o ffi_vspace.o ffi_qre.o parsing.o rsr_algorithm-verbose.o kem-verbose.o

LIB_OBJS:=hash.o rng.o

BUILD:=bin/build
BIN:=bin



folders:
	@echo -e "\n### Creating build folders\n"
	mkdir -p $(BUILD)

hash.o: folders
	@echo -e "\n### Compiling $@ (wrapper around openssl SHA512 implementation)\n"
	$(CC) $(CFLAGS) -c $(HASH_SRC) $(HASH_INCLUDE) -o $(BUILD)/$@

rng.o: folders
	@echo -e "\n### Compiling NIST rng.o\n"
	$(CC) $(CFLAGS) $(NO_RNG_WARNING) -c $(RNG_SRC) $(RNG_INCLUDE) -o $(BUILD)/$@



ffi_%.o: $(FFI_SRC)/ffi_%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(CFLAGS) -c $< $(FFI_INCLUDE) $(LIB) -o $(BUILD)/$@

%.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@\n"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -o $(BUILD)/$@

%-verbose.o: $(SRC)/%.c | folders
	@echo -e "\n### Compiling $@ (verbose mode)\n"
	$(CC) $(CFLAGS) -c $< $(INCLUDE) $(LIB) -D VERBOSE -o $(BUILD)/$@



rollo-II-128: $(ROLLO_OBJS) $(LIB_OBJS) | folders
	@echo -e "\n### Compiling ROLLO-II-128\n"
	$(CC) $(CFLAGS) $(MAIN_ROLLO) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

rollo-II-128-kat: $(ROLLO_OBJS) $(LIB_OBJS) | folders
	@echo -e "\n### Compiling ROLLO-II-128 KAT\n"
	$(CC) $(CFLAGS) $(MAIN_KAT) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -o $(BIN)/$@

rollo-II-128-verbose: $(ROLLO_OBJS_VERBOSE) $(LIB_OBJS) | folders
	@echo -e "\n### Compiling ROLLO-II-128 (verbose mode)\n"
	$(CC) $(CFLAGS) $(MAIN_ROLLO) $(addprefix $(BUILD)/, $^) $(INCLUDE) $(LIB) -D VERBOSE -o $(BIN)/$@



clean:
	rm -f PQCkemKAT_*
	rm -f vgcore.*
	rm -rf ./bin
