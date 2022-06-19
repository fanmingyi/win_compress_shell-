#pragma once

#include<Windows.h>
#include<wincrypt.h>

#define MD5LEN 16

class CPacker
{
public:
	bool Pack(const char const* szSrcExePath, const char const* szDstExePath);

private:
	DWORD GetAlign(DWORD dwValue);
	
private:
	//PE文件解析部分
	HANDLE m_hFile;
	HANDLE m_hFileMap;
	LPVOID m_pSrcPebuf;
	DWORD m_dwFileSize;
	PIMAGE_DOS_HEADER m_pDosHdr;
	PIMAGE_NT_HEADERS m_pNtHdr;
	PIMAGE_SECTION_HEADER m_pSecs;

	bool AnalyzePE(const char const* szSrcExePath);
	//
	LPVOID CPacker::RvaToFa(DWORD dwRva);

private:
	struct ImpInfo {
		char m_szDllName[64];
		DWORD m_dwImpCount;
		DWORD m_dwIATOff;
		DWORD m_aryHash[1024];
	};
	DWORD m_dwImpCnt;
	ImpInfo m_aryImpInfos[128];

	DWORD GetHash(char* fun_name);
	bool GetImpInfos();

private:
	struct SecInfo
	{
		DWORD m_dwOff;
		DWORD m_dwComSize;//压缩数据的偏移
		DWORD m_dwDecomOff;//解压缩数据的偏移RVA
		DWORD m_dwDecomSize;//解压缩后数据的大小

	};
	//压缩数据部分
	LPBYTE m_pComDataBuf;
	DWORD m_dwComDataSize;
	SecInfo* m_pSecInfos;
	DWORD m_dwSecCount;
	bool Compress();

private:
	//壳代码
	LPBYTE m_pCodeBuf;
	DWORD m_dwCodeSize;
	bool GetCode();
private:
	
	struct ComDataInfo {
		DWORD m_dwSecOff;//压缩数据的节偏移
		DWORD m_dwSecInfoCount;
		DWORD m_dwSecInfoOff;
		DWORD m_dwImpInfoCount;
		DWORD m_dwImpInfoOff;
		DWORD m_dwOep;
	};

	//节
	//这个节包含
	//1. 压缩数据的基础信息
	//2. 解压缩代码
	//3. 压缩数据
	LPBYTE m_pSecDataBuf;
	//m_pSecDataBuf保存的数据数据大小 已经对齐
	DWORD m_dwSecDataBufSize;
	bool GetSecData();

private:
	//节表
	//第一个节是原始的PE节
	//第二个节是m_pSecDataBuf
	IMAGE_SECTION_HEADER m_sechdrs[2];
	bool GetNewSecHdrs();
private:
	//新的PE头
	LPBYTE m_pNewPeHdrBuf;
	DWORD m_dwNewPeHdrBufSize;
	bool GetNewPeHdr();

private:
	//写入文件
	bool WriteNewPE2File(const char *szDstPath);

};

