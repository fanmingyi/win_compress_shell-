#include "pch.h"
#include "CPacker.h"
#include <compressapi.h>
#pragma comment(lib,"Cabinet.lib")

bool CPacker::Pack(const char const* szSrcExePath, const char const* szDstExePath)
{
	/*
	* 1.����PE
	*/
	if (!AnalyzePE(szSrcExePath))
	{
		return false;
	}


	/*
	* ��ȡ�������Ϣ
	*/

	if (!GetImpInfos())
	{
		return false;
	}

	/*
	* 2.ѹ���� ��ȡѹ������
	*/
	if (!Compress())
	{
		return false;
	}

	/*
	* 3.��ȡ�Ǵ���
	*/
	if (!GetCode())
	{
		return false;
	}

	/*
	* 4.�������PE
	*/

	//1. ׼����������
	if (!GetSecData())
	{
		return false;
	}

	//2. �����µĽڱ�
	if (!GetNewSecHdrs())
	{
		return false;
	}


	//3.�����µ�PEͷ
	if (!GetNewPeHdr())
	{
		return false;
	}


	//4. д���ļ�

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

	//���뻺����
	m_pSrcPebuf = new BYTE[m_dwFileSize];
	//��ȡPE�ļ�
	DWORD dwBytesWrited = 0;
	ReadFile(m_hFile,m_pSrcPebuf,m_dwFileSize,&dwBytesWrited,NULL);


	//DOSͷ
	m_pDosHdr = (PIMAGE_DOS_HEADER)m_pSrcPebuf;
	//NTͷ
	m_pNtHdr = (PIMAGE_NT_HEADERS)((DWORD)m_pSrcPebuf + m_pDosHdr->e_lfanew);
	//��ͷ
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
	//��ȡ�����
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
			m_aryImpInfos[dwIdx].m_aryHash[dwIdxIAT] = GetHash((char*)RvaToFa(*pINT) + 2);//�õ����뺯���Ĺ�ϣ��ֵ
		
			memset((char*)RvaToFa(*pINT), 0, strlen((char*)RvaToFa(*pINT)));//��������
			 
			++pINT;
			++dwIdxIAT;
		}
		m_aryImpInfos[dwIdx].m_dwImpCount = dwIdxIAT;

		dwIdx++;
	
	}
	m_dwImpCnt = dwIdx;
	//Ĩ�������
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

	//// ��ѯ�����С
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

	//ѭ���Խ�ѹ��
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

	//��ȡ��ѹ������
	ReadFile(m_hFile, m_pCodeBuf, m_dwCodeSize, &dwBytesWrited, 0);
	CloseHandle(m_hFile);

	return true;
}

bool CPacker::GetSecData()
{
	//ѹ��������Ϣ
	ComDataInfo cdi = {};
	//������ƫ��
	cdi.m_dwSecOff = sizeof(ComDataInfo) + m_dwCodeSize;//�������ݷ���code֮��
	//ѹ���Ľ����ܴ�С
	DWORD dwComDataSize = m_pSecInfos[m_dwSecCount - 1].m_dwOff + m_pSecInfos[m_dwSecCount - 1].m_dwComSize;
	//�洢����Ϣ������
	cdi.m_dwSecInfoOff = cdi.m_dwSecOff+ dwComDataSize;
	//��������
	cdi.m_dwSecInfoCount = m_dwSecCount;
	//���ڴ�ŵ���ı��ƫ��
	cdi.m_dwImpInfoOff = cdi.m_dwSecInfoOff + sizeof(SecInfo)* m_dwSecCount;
	//���������
	cdi.m_dwImpInfoCount = m_dwImpCnt;
	
	cdi.m_dwOep = m_pNtHdr->OptionalHeader.AddressOfEntryPoint;



	//�����ڴ�
	DWORD dwRealSize = cdi.m_dwImpInfoOff+sizeof(ImpInfo)*m_dwImpCnt;
	//����SectionAlignment
	m_dwSecDataBufSize = GetAlign(dwRealSize);

	m_pSecDataBuf = new BYTE[m_dwSecDataBufSize];

	if (m_pSecDataBuf == nullptr)
	{
		return false;
	}


	//��������
	memset(m_pSecDataBuf, 0, m_dwSecDataBufSize);

	memcpy(m_pSecDataBuf, &cdi, sizeof ComDataInfo);//����ѹ��������Ϣ

	memcpy(m_pSecDataBuf + sizeof(cdi), m_pCodeBuf, m_dwCodeSize);//��������

	memcpy(m_pSecDataBuf  + cdi.m_dwSecOff,
		m_pComDataBuf,
		m_dwComDataSize);//����


	//��������Ϣ
	memcpy(m_pSecDataBuf + cdi.m_dwSecInfoOff,m_pSecInfos,sizeof(SecInfo)*m_dwSecCount);//��������Ϣ

	memcpy(m_pSecDataBuf + cdi.m_dwImpInfoOff, m_aryImpInfos, sizeof(ImpInfo) * m_dwImpCnt);
	return true;
}

bool CPacker::GetNewSecHdrs()
{
	memset(&m_sechdrs, 0, sizeof(m_sechdrs));
	//�����һ���� Ԥ����ԭԭʼPE��Ϣ
	strcpy((char*)m_sechdrs[0].Name, "upxplus");
	m_sechdrs[0].PointerToRawData = 0;
	m_sechdrs[0].SizeOfRawData = 0;
	m_sechdrs[0].VirtualAddress = m_pSecs[0].VirtualAddress;
	m_sechdrs[0].Misc.VirtualSize = m_pNtHdr->OptionalHeader.SizeOfImage;


	m_sechdrs[0].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
		| IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;


	//����� ������ѹ������ ѹ������
	strcpy((char*)m_sechdrs[1].Name, ".nbs");
	//
	m_sechdrs[1].PointerToRawData = m_pNtHdr->OptionalHeader.SizeOfHeaders;
	m_sechdrs[1].SizeOfRawData = m_dwSecDataBufSize;
	//��ַƴ���ڵڶ�����֮��
	m_sechdrs[1].VirtualAddress = m_pSecs[0].VirtualAddress + m_sechdrs[0].Misc.VirtualSize;

	m_sechdrs[1].Misc.VirtualSize = m_dwSecDataBufSize;


	m_sechdrs[1].Characteristics = IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE
		| IMAGE_SCN_CNT_CODE | IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_UNINITIALIZED_DATA;



	return true;
}

bool CPacker::GetNewPeHdr()
{

	//Ϊ��PEͷ�����ڴ�
	m_dwNewPeHdrBufSize = m_pNtHdr->OptionalHeader.SizeOfHeaders;
	m_pNewPeHdrBuf = new BYTE[m_dwNewPeHdrBufSize];
	//
	if (m_pNewPeHdrBuf == nullptr)
	{
		return false;
	}
	//����ԭ����PEͷ
	memcpy(m_pNewPeHdrBuf, m_pDosHdr, m_dwNewPeHdrBufSize);


	//����
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)m_pNewPeHdrBuf; //DOSͷ

	IMAGE_NT_HEADERS32* pNtHeader = (IMAGE_NT_HEADERS32*)((DWORD)m_pNewPeHdrBuf + pDosHeader->e_lfanew);//NTͷ


	//��ͷ
	IMAGE_SECTION_HEADER* pSectionAry = (IMAGE_SECTION_HEADER*)((DWORD)pNtHeader + pNtHeader->FileHeader.SizeOfOptionalHeader + IMAGE_SIZEOF_FILE_HEADER + 4);

	//�����ڱ�
	memcpy(pSectionAry, &m_sechdrs[0], sizeof(m_sechdrs));


	//�޸����ֶ� 
	pNtHeader->FileHeader.NumberOfSections = 2;
	//�޸���ڵ�
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
	//д��PEͷ
	WriteFile(m_hFile, m_pNewPeHdrBuf, m_dwNewPeHdrBufSize, &dwBytesWrited, 0);
	//д�������
	WriteFile(m_hFile, m_pSecDataBuf, m_dwSecDataBufSize, &dwBytesWrited, 0);
	CloseHandle(m_hFile);

	return true;
}
