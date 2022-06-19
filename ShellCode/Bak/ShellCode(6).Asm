.586
.model flat,stdcall
option casemap:none

   include windows.inc
   include user32.inc
   include kernel32.inc
   
   includelib user32.lib
   includelib kernel32.lib



.data
   ClassName db "MainWinClass",0
   AppName  db "Main Window",0

.data?
   hInstance HINSTANCE ?
   CommandLine LPSTR ?


GetKernelBase proto

MyGetProcAddress proto  hDll:HINSTANCE,pName:LPCTSTR
MyGetProcAddressHash proto  hDll:HINSTANCE,pName:LPCTSTR
mystrcmp  proto
mymemset proto
mymemcmp proto
;LoadDll proto  lpMapAddr:LPBYTE,hInst:HANDLE,pEnv:ptr Environment
GetHash proto


Environment struc
	m_pfnLoadLibraryA dd 0
	m_pfnGetProcAddress dd 0
	m_pfnCreateDecompressor dd 0 
	m_pfnDecompress dd 0 
	m_pfnVirtualAlloc dd 0
	m_pfnRtlMoveMemory dd 0
	m_pfnVirtualProtect dd 0
Environment ends


ComInfo struc
	;m_dwOff dd 0
	;m_dwComSize dd 0   ;压缩后大小1232
	;m_dwDecomSize dd 0 ;解压大小	
	 m_dwSecOff dd 0;//压缩数据的节偏移
	 m_dwSecInfoCount dd 0;
	 m_dwSecInfoOff dd 0;
	 m_dwImpInfoCount dd 0;
	 m_dwImpInfoOff dd 0;
	 m_dwOep dd 0;
ComInfo ends

SecInfo struct
	 m_dwOff 	 	dd 0;
	 m_dwComSize 	dd 0;//压缩数据的偏移
	 m_dwDecomOff   dd 0;//解压缩数据的偏移RVA
	 m_dwDecomSize  dd 0;//解压缩后数据的大小
SecInfo ends
	
ImpInfo struct
	m_szDllName db 64 dup(0);
	m_dwImpCount dd 0;
	m_dwIATOff dd 0;
	m_aryHash dd 1024 dup(0);
ImpInfo ends




.code
CODE_START:
    jmp start	
	g_szLoadLibraryA db "LoadLibraryA",0
	g_szGetProcAddress db "GetProcAddress",0
	g_szCabinet db "Cabinet",0
	g_szCreateDecompressor db "CreateDecompressor",0
	g_szDecompress db "Decompress",0
	g_szVirtualAlloc db "VirtualAlloc",0
	g_szRtlMoveMemory db "RtlMoveMemory",0
	g_szNtDll db "ntdll",0
	g_szVirtualProtect db "VirtualProtect",0
	g_env Environment <>
	

Init proc uses ebx esi
	LOCAL hKernel:HMODULE
	LOCAL hCabinet:HMODULE
	LOCAL hNtdll:HMODULE
	
	;重定位
	;指向pop ebx 
	call NEXT
NEXT:
	pop ebx	
	sub ebx,offset NEXT;偏移
	
	;定位Environment
	mov eax,offset g_env
	add eax,ebx
	mov esi,eax
	assume esi:ptr Environment
	
	
	invoke GetKernelBase
	mov hKernel,eax
	
	
	;kernel32相关
	mov eax,offset g_szGetProcAddress
	add eax,ebx
	invoke MyGetProcAddress,hKernel,eax
	mov [esi].m_pfnGetProcAddress,eax
	
	mov eax,offset g_szLoadLibraryA
	add eax,ebx
	push eax
	push hKernel
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnLoadLibraryA,eax
	
	mov eax,offset g_szVirtualAlloc
	add eax,ebx
	push eax
	push hKernel
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnVirtualAlloc,eax
	
	
	
	mov eax,offset g_szVirtualProtect
	add eax,ebx
	push eax
	push hKernel
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnVirtualProtect,eax
	
	
	;压缩相关
	mov eax,offset g_szCabinet
	add eax,ebx
	push eax
	call [esi].m_pfnLoadLibraryA
	mov hCabinet,eax
	
	
	
	
	mov eax,offset g_szCreateDecompressor
	add eax,ebx
	push eax
	push hCabinet
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnCreateDecompressor,eax  
	
	
	
	mov eax,offset g_szDecompress
	add eax,ebx
	push eax
	push hCabinet
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnDecompress,eax  
	
	
	
	
	;g_szRtlMoveMemory db "RtlMoveMemory",0
	;g_szNtDll db "ntdll"
	
	;ntdll相关
	mov eax,offset g_szNtDll
	add eax,ebx
	push eax
	call [esi].m_pfnLoadLibraryA
	mov hNtdll,eax
	
	
	
	
	mov eax,offset g_szRtlMoveMemory
	add eax,ebx
	push eax
	push hNtdll
	call [esi].m_pfnGetProcAddress
	mov [esi].m_pfnRtlMoveMemory,eax  
	
	
	
	 mov eax,esi
	ret

Init endp	

GetKernelBase proc

	assume fs:nothing
		mov  eax, dword ptr fs : [030h]
		mov  eax, dword ptr      [eax +  0Ch]
		mov  eax, dword ptr      [eax + 0Ch]
		mov  eax, dword ptr      [eax]
		mov  eax, dword ptr  	 [eax]
		mov  eax, dword ptr  	 [eax + 18h]
		ret
GetKernelBase endp
MyGetProcAddress proc  uses esi ebx edi  hDll:HINSTANCE,pName:LPCTSTR
	LOCAL @dwAddressOfNames:DWORD
	LOCAL @dwCnt:DWORD

	mov esi,hDll
	assume esi:ptr IMAGE_DOS_HEADER
	mov esi,[esi].e_lfanew
	add esi,hDll
	
	assume esi:ptr IMAGE_NT_HEADERS
	;得到导出表位置
	mov esi,[esi].OptionalHeader.DataDirectory[0].VirtualAddress
	add esi,hDll
	
	assume esi:ptr IMAGE_EXPORT_DIRECTORY
	
	.if pName > 0ffffh ;名称
		;导出名称表地址
		mov eax,[esi].AddressOfNames
		add eax,hDll
		mov @dwAddressOfNames,eax
	
		;遍历导出名称表，查找对应函数
		mov eax,[esi].NumberOfNames
		mov @dwCnt,eax
		dec @dwCnt
 		.while sdword ptr @dwCnt> 0
			;数组首地址
			mov ebx,@dwAddressOfNames
			mov eax,@dwCnt
			mov eax,[ebx+ eax * sizeof DWORD]
			add eax,hDll 

			;对比字符串
			push eax
			push pName
			call mystrcmp
			add esp,8
			
			
			;invoke crt_strcmp,pName,eax
			.if eax == 0
			
				mov eax,@dwCnt
				mov ebx,[esi].AddressOfNameOrdinals
				add ebx,hDll
				movzx eax,word ptr [ebx+eax*sizeof WORD]
				
				;获取地址
				mov ebx,[esi].AddressOfFunctions
				add ebx,hDll
				mov eax,[ebx+eax*sizeof DWORD]
				
				add eax,hDll
				ret
			.endif
		
			dec @dwCnt
		.endw
	
	.else
		;获取导出地址表中的下标索引
		
		ret	
	.endif
	

	xor eax,eax	
	ret

MyGetProcAddress endp 

MyGetProcAddressHash proc  uses esi ebx edi  hDll:HINSTANCE,pName:LPCTSTR
	LOCAL @dwAddressOfNames:DWORD
	LOCAL @dwCnt:DWORD

	mov esi,hDll
	assume esi:ptr IMAGE_DOS_HEADER
	mov esi,[esi].e_lfanew
	add esi,hDll
	
	assume esi:ptr IMAGE_NT_HEADERS
	;得到导出表位置
	mov esi,[esi].OptionalHeader.DataDirectory[0].VirtualAddress
	add esi,hDll
	
	assume esi:ptr IMAGE_EXPORT_DIRECTORY
	
	;.if pName > 0ffffh ;名称
		;导出名称表地址
		mov eax,[esi].AddressOfNames
		add eax,hDll
		mov @dwAddressOfNames,eax
	
		;遍历导出名称表，查找对应函数
		mov eax,[esi].NumberOfNames
		mov @dwCnt,eax
		dec @dwCnt
 		.while @dwCnt> 0
			;数组首地址
			mov ebx,@dwAddressOfNames
			mov eax,@dwCnt
			mov eax,[ebx+ eax * sizeof DWORD]
			add eax,hDll 

			;对比字符串
			push eax
			call GetHash
			add esp,4
			
			;invoke crt_strcmp,pName,eax
			.if eax == pName
				;int 3;
				mov eax,@dwCnt
				mov ebx,[esi].AddressOfNameOrdinals
				add ebx,hDll
				movzx eax,word ptr [ebx+eax*sizeof WORD]
				
				;获取地址
				mov ebx,[esi].AddressOfFunctions
				add ebx,hDll
				mov eax,[ebx+eax*sizeof DWORD]
				
				add eax,hDll
				ret
			.endif
		
			dec @dwCnt
		.endw
	
	;.else
		;获取导出地址表中的下标索引
		
	;	ret	
	;.endif
	

	xor eax,eax	
	ret

MyGetProcAddressHash endp 
; ---------------------------------------------------------------------------

GetHash proc
	push ebp
	mov ebp,esp
	push ecx
	mov dword ptr ss:[ebp-4],0
	CON:
	mov eax,dword ptr ss:[ebp+8]
	movsx ecx,byte ptr ds:[eax]
	test ecx,ecx
	je DONE
	mov edx,dword ptr ss:[ebp-4]
	shl edx,19h
	mov eax,dword ptr ss:[ebp-4]
	shr eax,7h
	or edx,eax
	mov dword ptr ss:[ebp-4],edx
	mov ecx,dword ptr ss:[ebp+8]
	movsx edx,byte ptr ds:[ecx]
	add edx,dword ptr ss:[ebp-4]
	mov dword ptr ss:[ebp-4],edx
	mov eax,dword ptr ss:[ebp+8]
	add eax,1
	mov dword ptr ss:[ebp+8],eax
	jmp CON
	DONE:
	mov eax,dword ptr ss:[ebp-4]
	mov esp,ebp
	pop ebp
	ret 


GetHash endp



Entry proc
	LOCAL @hDecom:HANDLE
	LOCAL @pDecomBuf:LPBYTE
	LOCAL @dwDecomSizeRet:DWORD
	LOCAL @dwModuleBase:DWORD
	LOCAL @dwSecBase:DWORD
	LOCAL @pSecData:LPVOID
	LOCAL @pSecInfo:ptr SecInfo
	LOCAL @dwSecInfoCnt:DWORD
	LOCAL @pImpInfo:ptr ImpInfo
	LOCAL @dwImpInfoCnt:DWORD
	LOCAL @dwCntTmp:DWORD 
	LOCAL @hDll:HMODULE
	LOCAL @dwOep:DWORD
	
	
	;初始化,获取所属的API地址
	invoke Init
	mov esi,eax
	assume esi:ptr Environment
	
	assume fs:nothing
	mov eax,fs:[30h]
	mov eax,[eax+8] ;模块基质
	mov @dwModuleBase,eax
	
	;获取偏移
	call NEXT
NEXT:
	pop ebx	
	sub ebx,offset NEXT;偏移
	
	
	;定位到ComInfo
	mov eax,offset CODE_START
	add eax,ebx
	sub eax,size ComInfo
	mov @dwSecBase,eax
	
	
	;定位各个数据的位置
	mov edi,@dwSecBase
	assume edi:ptr ComInfo
	
	;OEP
	
	mov eax,[edi].m_dwOep
	add eax,@dwModuleBase
	mov @dwOep,eax
	
	;压缩节数据的位置
	mov eax,[edi].m_dwSecOff
	add eax,@dwSecBase
	mov @pSecData,eax
	

	;压缩节信息的位置
	mov eax,[edi].m_dwSecInfoOff
	add eax,@dwSecBase
	mov @pSecInfo,eax
	
	
	mov eax,[edi].m_dwSecInfoCount
	mov @dwSecInfoCnt,eax
	
	;导入表信息的位置
	mov eax,[edi].m_dwImpInfoOff
	add eax,@dwSecBase
	mov @pImpInfo,eax
	
	mov eax,[edi].m_dwImpInfoCount
	mov @dwImpInfoCnt,eax
	
	
	assume edi:nothing
	;解压缩
	
	lea eax,@hDecom
	push eax
	push NULL
	push 4
	call [esi].m_pfnCreateDecompressor
	 
	
	
	
	;拷贝节数据
	
	
	mov edi,@pSecInfo
	assume edi:ptr SecInfo
	xor ecx,ecx
	
	.while ecx < @dwSecInfoCnt 
		push ecx 
		
		;传出参数入栈 
		lea eax,@dwDecomSizeRet
		push eax
		;解压缩大小入栈
	
		push [edi].m_dwDecomSize
		
		;解压缩数据地址入栈
		mov eax,[edi].m_dwDecomOff
		add eax,@dwModuleBase
		push eax
		
		
		;压缩数据的大小入栈
		push [edi].m_dwComSize
		
		
		;压缩数据的地址入栈
		mov eax,[edi].m_dwOff
		add eax,@pSecData
		push eax
		
		
		;压缩句柄入栈
		push @hDecom
		
		call [esi].m_pfnDecompress
		

		
		pop ecx
		inc ecx
		add edi,size SecInfo
	.endw
	assume edi:nothing
	

	
	
	;处理导入表
	mov edi,@pImpInfo
	assume edi:ptr ImpInfo
	xor ecx,ecx
	
	.while ecx< @dwImpInfoCnt
		push ecx
		
		;加载dll
		
		lea eax,[edi].m_szDllName
		push eax
		
		call [esi].m_pfnLoadLibraryA
		mov @hDll,eax
		
		xor ecx,ecx
		
		.while ecx< [edi].m_dwImpCount
			lea eax,[edi].m_aryHash
			invoke MyGetProcAddressHash,@hDll,dword ptr[eax+ecx*sizeof DWORD]
			
			;存入IAT
			mov edx,[edi].m_dwIATOff
			add edx,@dwModuleBase
			int 3;
			mov  dword ptr[edx +ecx * sizeof DWORD],eax
			  
			
			inc ecx
			
		.endw
		
		
		
		
		pop ecx
		add edi,size ImpInfo
		inc ecx
	.endw
	assume edi:nothing
	

	mov eax,@dwOep
	ret

Entry endp


mystrcmp  proc

        .FPO    ( 0, 2, 0, 0, 0, 0 )

        mov     edx,[esp + 4]   ; edx = src
        mov     ecx,[esp + 8]   ; ecx = dst

        test    edx,3
        jnz     short dopartial

        align   4
dodwords:
        mov     eax,[edx]

        cmp     al,[ecx]
        jne     short donene
        or      al,al
        jz      short doneeq
        cmp     ah,[ecx + 1]
        jne     short donene
        or      ah,ah
        jz      short doneeq

        shr     eax,16

        cmp     al,[ecx + 2]
        jne     short donene
        or      al,al
        jz      short doneeq
        cmp     ah,[ecx + 3]
        jne     short donene
        add     ecx,4
        add     edx,4
        or      ah,ah
        jnz     short dodwords

        align   4
doneeq:
        xor     eax,eax
        ret

        align   4
donene:
        ; The instructions below should place -1 in eax if src < dst,
        ; and 1 in eax if src > dst.

        sbb     eax,eax
        sal     eax,1
        inc     eax
        ret

        align   4
dopartial:
        test    edx,1
        jz      short doword

        mov     al,[edx]
        inc     edx
        cmp     al,[ecx]
        jne     short donene
        inc     ecx
        or      al,al
        jz      short doneeq

        test    edx,2
        jz      short dodwords


        align   4
doword:
        mov     ax,[edx]
        add     edx,2
        cmp     al,[ecx]
        jne     short donene
        or      al,al
        jz      short doneeq
        cmp     ah,[ecx + 1]
        jne     short donene
        or      ah,ah
        jz      short doneeq
        add     ecx,2
        jmp     short dodwords

mystrcmp  endp

mymemset proc

        .FPO    ( 0, 3, 0, 0, 0, 0 )

        mov     edx,[esp + 0ch] ; edx = "count"
        mov     ecx,[esp + 4]   ; ecx points to "dst"

        test    edx,edx         ; 0?
        jz      short toend     ; if so, nothing to do

        xor     eax,eax
        mov     al,[esp + 8]    ; the byte "value" to be stored


; Align address on dword boundary

        push    edi             ; preserve edi
        mov     edi,ecx         ; edi = dest pointer

        cmp     edx,4           ; if it's less then 4 bytes
        jb      tail            ; tail needs edi and edx to be initialized

        neg     ecx
        and     ecx,3           ; ecx = # bytes before dword boundary
        jz      short dwords    ; jump if address already aligned

        sub     edx,ecx         ; edx = adjusted count (for later)
adjust_loop:
        mov     [edi],al
        inc     edi
        dec     ecx
        jnz     adjust_loop

dwords:
; set all 4 bytes of eax to [value]
        mov     ecx,eax         ; ecx=0/0/0/value
        shl     eax,8           ; eax=0/0/value/0

        add     eax,ecx         ; eax=0/0val/val

        mov     ecx,eax         ; ecx=0/0/val/val

        shl     eax,10h         ; eax=val/val/0/0

        add     eax,ecx         ; eax = all 4 bytes = [value]

; Set dword-sized blocks
        mov     ecx,edx         ; move original count to ecx
        and     edx,3           ; prepare in edx byte count (for tail loop)
        shr     ecx,2           ; adjust ecx to be dword count
        jz      tail            ; jump if it was less then 4 bytes

        rep     stosd
main_loop_tail:
        test    edx,edx         ; if there is no tail bytes,
        jz      finish          ; we finish, and it's time to leave
; Set remaining bytes

tail:
        mov     [edi],al        ; set remaining bytes
        inc     edi

        dec     edx             ; if there is some more bytes
        jnz     tail            ; continue to fill them

; Done
finish:
        mov     eax,[esp + 8]   ; return dest pointer
        pop     edi             ; restore edi

        ret

toend:
        mov     eax,[esp + 4]   ; return dest pointer

        ret

mymemset  endp

mymemcmp  proc

        .FPO    ( 0, 3, 0, 0, 0, 0 )

        mov     eax,[esp+0ch]   ; eax = counter
        test    eax,eax         ; test if counter is zero
        jz      short retnull   ; return 0

        mov     edx,[esp+4]     ; edx = buf1
        push    esi
        push    edi
        mov     esi,edx         ; esi = buf1
        mov     edi,[esp+10h]   ; edi = buf2

; Check for dword (32 bit) alignment
        or      edx,edi
        and     edx,3           ; edx=0 iff buf1 are buf2 are aligned
        jz      short dwords

; Strings are not aligned. If the caller knows the strings (buf1 and buf2) are
; different, the function may be called with length like -1. The difference
; may be found in the last dword of aligned string, and because the other
; string is misaligned it may cause page fault. So, to be safe. the comparison
; must be done byte by byte.
        test    eax,1
        jz      short main_loop

        mov     cl,[esi]
        cmp     cl,[edi]
        jne     short not_equal
        inc     esi
        inc     edi
        dec     eax
        jz      short done      ; eax is already 0

main_loop:
        mov     cl,[esi]
        mov     dl,[edi]
        cmp     cl,dl
        jne     short not_equal

        mov     cl,[esi+1]
        mov     dl,[edi+1]
        cmp     cl,dl
        jne     short not_equal

        add     edi,2
        add     esi,2

        sub     eax,2
        jnz     short main_loop
done:
        pop     edi
        pop     esi
retnull:
        ret                     ; _cdecl return


dwords:
        mov     ecx,eax
        and     eax,3           ; eax= counter for tail loop

        shr     ecx,2
        jz      short tail_loop_start
                                ; counter was >=4 so may check one dword
        repe     cmpsd

        jz      short tail_loop_start

; in last dword was difference
        mov     ecx,dword ptr[esi-4]     ; load last dword from buf1 to ecx
        mov     edx,[edi-4]     ; load last dword from buf2 to edx
        cmp     cl,dl           ; test first bytes
        jne     short difference_in_tail
        cmp     ch,dh           ; test seconds bytes
        jne     short difference_in_tail
        shr     ecx,10h
        shr     edx,10h
        cmp     cl,dl           ; test third bytes
        jne     short difference_in_tail
        cmp     ch,dh           ; they are different, but each one is bigger?
;       jmp     short difference_in_tail

difference_in_tail:
        mov     eax,0
                                ; buf1 < buf2 buf1 > buf2
not_equal:
        sbb     eax,eax         ; AX=-1, CY=1 AX=0, CY=0
        pop     edi             ; counter
        sbb     eax,-1          ; AX=-1 AX=1
        pop     esi
        ret                     ; _cdecl return

; in tail loop we test last three bytes (esi and edi are aligned on dword
; boundary)
tail_loop_start:

        test    eax,eax         ; eax is counter%4 (number of bytes for tail
                                ; loop)
        jz      short done      ; taken if there is no tail bytes
        mov     edx,dword ptr[esi]       ; load dword from buf1
        mov     ecx,dword ptr[edi]       ; load dword from buf2
        cmp     dl,cl           ; test first bytes
        jne     short difference_in_tail
        dec     eax             ; counter--
        jz      short tail_done
        cmp     dh,ch           ; test second bytes
        jne     short difference_in_tail
        dec     eax             ; counter--
        jz      short tail_done
        and     ecx,00ff0000h   ; test third bytes
        and     edx,00ff0000h
        cmp     edx,ecx
        jne     short difference_in_tail
        dec     eax
tail_done:
        pop     edi
        pop     esi
        ret                     ; _cdecl return

mymemcmp  endp




start:

	invoke Entry
	jmp eax



end start
