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
	//PE�ļ���������
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
		DWORD m_dwComSize;//ѹ�����ݵ�ƫ��
		DWORD m_dwDecomOff;//��ѹ�����ݵ�ƫ��RVA
		DWORD m_dwDecomSize;//��ѹ�������ݵĴ�С

	};
	//ѹ�����ݲ���
	LPBYTE m_pComDataBuf;
	DWORD m_dwComDataSize;
	SecInfo* m_pSecInfos;
	DWORD m_dwSecCount;
	bool Compress();

private:
	//�Ǵ���
	LPBYTE m_pCodeBuf;
	DWORD m_dwCodeSize;
	bool GetCode();
private:
	
	struct ComDataInfo {
		DWORD m_dwSecOff;//ѹ�����ݵĽ�ƫ��
		DWORD m_dwSecInfoCount;
		DWORD m_dwSecInfoOff;
		DWORD m_dwImpInfoCount;
		DWORD m_dwImpInfoOff;
		DWORD m_dwOep;
	};

	//��
	//����ڰ���
	//1. ѹ�����ݵĻ�����Ϣ
	//2. ��ѹ������
	//3. ѹ������
	LPBYTE m_pSecDataBuf;
	//m_pSecDataBuf������������ݴ�С �Ѿ�����
	DWORD m_dwSecDataBufSize;
	bool GetSecData();

private:
	//�ڱ�
	//��һ������ԭʼ��PE��
	//�ڶ�������m_pSecDataBuf
	IMAGE_SECTION_HEADER m_sechdrs[2];
	bool GetNewSecHdrs();
private:
	//�µ�PEͷ
	LPBYTE m_pNewPeHdrBuf;
	DWORD m_dwNewPeHdrBufSize;
	bool GetNewPeHdr();

private:
	//д���ļ�
	bool WriteNewPE2File(const char *szDstPath);

};

