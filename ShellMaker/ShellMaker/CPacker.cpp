#include "pch.h"
#include "CPacker.h"
#include <compressapi.h>
#pragma comment(lib,"Cabinet.lib")

bool CPacker::Pack(const char const* szSrcExePath, const char const* szDstExePath)
{
	/*
	* 1.解析PE
	*/
	if (!AnalyzePE(szSrcExePath))
	{
		return false;
	}


	/*
	* 获取导入表信息
	*/

	if (!GetImpInfos())
	{
		return false;
	}

	/*
	* 2.压缩节 获取压缩数据
	*/
	if (!Compress())
	{
		return false;
	}

	/*
	* 3.获取壳代码
	*/
	if (!GetCode())
	{
		return false;
	}

	/*
	* 4.构造带壳PE
	*/

	//1. 准备节区数据
	if (!GetSecData())
	{
		return false;
	}

	//2. 构造新的节表
	if (!GetNewSecHdrs())
	{
		return false;
	}


	//3.构造新的PE头
	if (!GetNewPeHdr())
	{
		return false;
	}


	//4. 写入文件

	if (!WriteNewPE2File(szDstExePath))
	{
		return false;
	}


	return true;
}

DWORD CPacker::GetAlign(DWORD dwValue)
{
	if (dwValue % m_pNtHdr->OptionalHeader.SectionAlignment == 0)
	{
		return dwValue;
	}



	return (dwValue / m_pNtHdr->OptionalHeader.SectionAlignment + 1) * m_pNtHdr->OptionalHeader.SectionAlignment;
}

bool CPacker::AnalyzePE(const char const* szSrcExePath)
{
	m_hFile = CreateFile(szSrcExePath,
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (m_hFile == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	m_dwFileSize = GetFileSize(m_hFile, NULL);

	//申请缓冲区
	m_pSrcPebuf = new BYTE[m_dwFileSize];
	//读取PE文件
	DWORD dwBytesWrited = 0;
	ReadFile(m_hFile,m_pSrcPebuf,m_dwFileSize,&dwBytesWrited,NULL);


	//DOS头
	m_pDosHdr = (PIMAGE_DOS_HEADER)m_pSrcPebuf;
	//NT头
	m_pNtHdr = (PIMAGE_NT_HEADERS)((DWORD)m_pSrcPebuf + m_pDosHdr->e_lfanew);
	//节头
	m_pSecs = (PIMAGE_SECTION_HEADER)((DWORD)&m_pNtHdr->OptionalHeader + m_pNtHdr->FileHeader.SizeOfOptionalHeader);


	return true;
}

DWORD CPacker::GetHash(char* fun_name)
{

	DWORD digest = 0;
	while (*fun_name)
	{
		digest = ((digest<<25)|(digest>>7));
		digest = digest + *fun_name;
		fun_name++;
	}
	return digest;
}
LPVOID CPacker::RvaToFa(DWORD dwRva) {

	if (dwRva < m_pNtHdr->OptionalHeader.SizeOfHeaders)
	{
		return (LPVOID)(dwRva + (DWORD)m_pSrcPebuf);
	}

	PIMAGE_SECTION_HEADER pSection = m_pSecs;

	for (DWORD i = 0; i < m_pNtHdr->FileHeader.NumberOfSections; i++)
	{
		if (dwRva >= pSection[i].VirtualAddress && dwRva < pSection[i].VirtualAddress + pSection[i].SizeOfRawData)
		{
			DWORD dw = (dwRva - pSection[i].VirtualAddress) + pSection[i].PointerToRawData + (DWORD)m_pSrcPebuf;
			return (LPVOID)dw;
		}
	}
	return NULL;
}
bool CPacker::GetImpInfos()
{
	//获取导入表
	PIMAGE_IMPORT_DESCRIPTOR pImpDes = (PIMAGE_IMPORT_DESCRIPTOR)RvaToFa(m_pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	IMAGE_IMPORT_DESCRIPTOR zeroImpDes = {};

	m_dwImpCnt = 0;
	DWORD dwIdx = 0;

	while (memcmp(&pImpDes[dwIdx], &zeroImpDes, sizeof(zeroImpDes)) != 0)
	{
		strcpy(m_aryImpInfos[dwIdx].m_szDllName, (char*)RvaToFa(pImpDes[dwIdx].Name));
		 memset((char*)RvaToFa(pImpDes[dwIdx].Name), 0, strlen((char*)RvaToFa(pImpDes[dwIdx].Name)));
		m_aryImpInfos[dwIdx].m_dwIATOff = pImpDes[dwIdx].FirstThunk;


		LPDWORD pINT = (LPDWORD)RvaToFa(pImpDes[dwIdx].OriginalFirstThunk);

		DWORD dwIdxIAT = 0;

		while (*pINT != NULL)
		{
			m_aryImpInfos[dwIdx].m_aryHash[dwIdxIAT] = GetHash((char*)RvaToFa(*pINT) + 2);//得到导入函数的哈希数值
		
			memset((char*)RvaToFa(*pINT), 0, strlen((char*)RvaToFa(*pINT)));//摸掉名称
			 
			++pINT;
			++dwIdxIAT;
		}
		m_aryImpInfos[dwIdx].m_dwImpCount = dwIdxIAT;

		dwIdx++;
	
	}
	m_dwImpCnt = dwIdx;
	//抹掉导入表
	memset(pImpDes, 0, dwIdx * sizeof(IMAGE_IMPORT_DESCRIPTOR));

	return true;
}

bool CPacker::Compress()
{


	COMPRESSOR_HANDLE hCompressor = NULL;


	//  Create an XpressHuff compressor.
	bool Success = ::CreateCompressor(
		COMPRESS_ALGORITHM_XPRESS_HUFF, //  Compression Algorithm
		NULL,                           //  Optional allocation routine
		&hCompressor);                   //  Handle

	if (!Success)
	{
		return false;
	}

	//// 查询缓存大小
	//DWORD dwCompressedBufferSize;
	//::Compress(
	//	hCompressor,                  //  Compressor Handle
	//	m_pSrcPebuf,                 //  Input buffer, Uncompressed data
	//	m_dwFileSize,               //  Uncompressed data size
	//	NULL,                        //  Compressed Buffer
	//	0,                           //  Compressed Buffer size
	//	&dwCompressedBufferSize);      //  Compressed Data size


	DWORD dwCompressedBufferSize = m_dwFileSize;

	m_pComDataBuf = new BYTE[dwCompressedBufferSize];

	if (m_pComDataBuf == nullptr)
	{
		return false;
	}

	//循环对节压缩
	m_dwSecCount = m_pNtHdr->FileHeader.NumberOfSections;

	m_pSecInfos = new SecInfo[m_dwSecCount];
	DWORD dwOff = 0;
	m_dwComDataSize = 0;
	for (size_t i = 0; i < m_dwSecCount; i++)
	{
		m_pSecInfos[i].m_dwOff = dwOff;
		m_pSecInfos[i].m_dwDecomSize = m_pSecs[i].SizeOfRawData;
		m_pSecInfos[i].m_dwDecomOff = m_pSecs[i].VirtualAddress;

		Success = ::Compress(
			hCompressor,                  //  Compressor Handle
			(LPBYTE)m_pSrcPebuf + m_pSecs[i].PointerToRawData,                 //  Input buffer, Uncompressed data
			m_pSecInfos[i].m_dwDecomSize,               //  Uncompressed data size
			m_pComDataBuf + m_pSecInfos[i].m_dwOff,                        //  Compressed Buffer
			m_pSecInfos[i].m_dwDecomSize,                           //  Compressed Buffer size
			&m_pSecInfos[i].m_dwComSize);      //  Compressed Data size

		dwOff += m_pSecInfos[i].m_dwComSize;
		m_dwComDataSize += m_pSecInfos[i].m_dwComSize;
	}
	
	CloseCompressor(hCompressor);
	return true;
}

bool CPacker::GetCode()
{
	m_dwCodeSize = 0x600;
	m_pCodeBuf = new BYTE[m_dwCodeSize];


	HANDLE	m_hFile = CreateFile("ShellCode.exe",
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (m_hFile == nullptr)
	{
		return false;
	}


	DWORD dwBytesWrited = 0;
	SetFilePointer(m_hFile, 0x400, NULL, FILE_BEGIN);

	//读取解压缩代码
	ReadFile(m_hFile, m_pCodeBuf, m_dwCodeSize, &dwBytesWrited, 0);
	CloseHandle(m_hFile);

	return true;
}

bool CPacker::GetSecData()
{
	//压缩数据信息
	ComDataInfo cdi = {};
	//节区的偏移
	cdi.m_dwSecOff = sizeof(ComDataInfo) + m_dwCodeSize;//节区数据放在code之后
	//压缩的节区总大小
	DWORD dwComDataSize = m_pSecInfos[m_dwSecCount - 1].m_dwOff + m_pSecInfos[m_dwSecCount - 1].m_dwComSize;
	//存储节信息的索引
	cdi.m_dwSecInfoOff = cdi.m_dwSecOff+ dwComDataSize;
	//节区数量
	cdi.m_dwSecInfoCount = m_dwSecCount;
	//后期存放导入的表的偏移
	cdi.m_dwImpInfoOff = cdi.m_dwSecInfoOff + sizeof(SecInfo)* m_dwSecCount;
	//导入表数量
	cdi.m_dwImpInfoCount = m_dwImpCnt;
	
	cdi.m_dwOep = m_pNtHdr->OptionalHeader.AddressOfEntryPoint;



	//申请内存
	DWORD dwRealSize = cdi.m_dwImpInfoOff+sizeof(ImpInfo)*m_dwImpCnt;
	//对齐SectionAlignment
	m_dwSecDataBufSize = GetAlign(dwRealSize);

	m_pSecDataBuf = new BYTE[m_dwSecDataBufSize];

	if (m_pSecDataBuf == nullptr)
	{
		return false;
	}


	//拷贝数据
	memset(m_pSecDataBuf, 0, m_dwSecDataBufSize);

	memcpy(m_pSecDataBuf, &cdi, sizeof ComDataInfo);//拷贝压缩数据信息

	memcpy(m_pSecDataBuf + sizeof(cdi), m_pCodeBuf, m_dwCodeSize);//拷贝代码

	memcpy(m_pSecDataBuf  + cdi.m_dwSecOff,
		m_pComDataBuf,
		m_dwComDataSize);//拷贝


	//拷贝节信息
	memcpy(m_pSecDataBuf + cdi.m_dwSecInfoOff,m_pSecInfos,sizeof(SecInfo)*m_dwSecCount);//拷贝节信息

	memcpy(m_pSecDataBuf + cdi.m_dwImpInfoOff, m_aryImpInfos, sizeof(ImpInfo) * m_dwImpCnt);
	return true;
}

bool CPacker::GetNewSecHdrs()
{
	memset(&m_sechdrs, 0, sizeof(m_sechdrs));
	//构造第一个节 预留还原原始PE信息
	strcpy((char*)m_sechdrs[0].Name, "upxplus");
	m_sechdrs[0].PointerToRawData = 0;
	m_sechdrs[0].SizeOfRawData = 0;
	m_sechdrs[0].VirtualAddress = m_pSecs[0].VirtualAddress;
	m_sechdrs[0].Misc.VirtualSize = m_pNtHdr->OptionalHeader.SizeOfImage;


	m_sechdrs[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
		| IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;


	//构造第 包含解压缩代码 压缩数据
	strcpy((char*)m_sechdrs[1].Name, ".nbs");
	//
	m_sechdrs[1].PointerToRawData = m_pNtHdr->OptionalHeader.SizeOfHeaders;
	m_sechdrs[1].SizeOfRawData = m_dwSecDataBufSize;
	//地址拼接在第二个节之后
	m_sechdrs[1].VirtualAddress = m_pSecs[0].VirtualAddress + m_sechdrs[0].Misc.VirtualSize;

	m_sechdrs[1].Misc.VirtualSize = m_dwSecDataBufSize;


	m_sechdrs[1].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
		| IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;



	return true;
}

bool CPacker::GetNewPeHdr()
{

	//为新PE头申请内存
	m_dwNewPeHdrBufSize = m_pNtHdr->OptionalHeader.SizeOfHeaders;
	m_pNewPeHdrBuf = new BYTE[m_dwNewPeHdrBufSize];
	//
	if (m_pNewPeHdrBuf == nullptr)
	{
		return false;
	}
	//拷贝原来的PE头
	memcpy(m_pNewPeHdrBuf, m_pDosHdr, m_dwNewPeHdrBufSize);


	//解析
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)m_pNewPeHdrBuf; //DOS头

	IMAGE_NT_HEADERS32* pNtHeader = (IMAGE_NT_HEADERS32*)((DWORD)m_pNewPeHdrBuf + pDosHeader->e_lfanew);//NT头


	//节头
	IMAGE_SECTION_HEADER* pSectionAry = (IMAGE_SECTION_HEADER*)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + 4);

	//拷贝节表
	memcpy(pSectionAry, &m_sechdrs[0], sizeof(m_sechdrs));


	//修复节字段 
	pNtHeader->FileHeader.NumberOfSections = 2;
	//修复入口点
	pNtHeader->OptionalHeader.AddressOfEntryPoint = m_sechdrs[1].VirtualAddress + sizeof(ComDataInfo);
	//
	pNtHeader->OptionalHeader.SizeOfImage = m_sechdrs[1].VirtualAddress + m_sechdrs[1].Misc.VirtualSize;


	return true;
}

bool CPacker::WriteNewPE2File(const char* szDstPath)
{


	HANDLE	m_hFile = CreateFile(szDstPath,
		GENERIC_WRITE,
		FILE_SHARE_READ,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	);

	if (m_hFile == nullptr)
	{
		return false;
	}


	DWORD dwBytesWrited = 0;
	//写入PE头
	WriteFile(m_hFile, m_pNewPeHdrBuf, m_dwNewPeHdrBufSize, &dwBytesWrited, 0);
	//写入节数据
	WriteFile(m_hFile, m_pSecDataBuf, m_dwSecDataBufSize, &dwBytesWrited, 0);
	CloseHandle(m_hFile);

	return true;
}
