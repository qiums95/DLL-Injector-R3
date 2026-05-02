#include "injector.h"
#include <iostream>
#include <string>

int main() {
	std::wstring dllPath;
	DWORD PID = 0;

	std::wcout << L"=========================================" << std::endl;
	std::wcout << L"           Manual Map Injector           " << std::endl;
	std::wcout << L"=========================================\n" << std::endl;

	// 获取 DLL 路径
	std::wcout << L"[DLLinject] Please enter the DLL path (You can drag and drop the file here):" << std::endl;
	std::wcout << L"> ";
	std::getline(std::wcin, dllPath);

	// 如果用户是直接把文件拖进控制台的，路径两边会带有双引号，这里自动去除
	if (!dllPath.empty() && dllPath.front() == L'\"' && dllPath.back() == L'\"') {
		dllPath = dllPath.substr(1, dllPath.length() - 2);
	}

	if (dllPath.empty()) {
		std::wcout << L"[DLLinject] Error: DLL path cannot be empty!" << std::endl;
		system("pause");
		return -1;
	}

	// 获取目标进程的 PID
	std::wcout << L"\n[DLLinject] Please enter the target Process ID (PID):" << std::endl;
	std::wcout << L"> ";
	std::cin >> PID;

	// 校验输入是否合法
	if (std::cin.fail() || PID == 0) {
		std::wcout << L"[DLLinject] Error: Invalid PID entered!" << std::endl;
		system("pause");
		return -2;
	}

	std::wcout << L"\n-----------------------------------------" << std::endl;
	std::wcout << L"[DLLinject] Target PID : " << PID << std::endl;
	std::wcout << L"[DLLinject] DLL Path   : " << dllPath << std::endl;
	std::wcout << L"-----------------------------------------\n" << std::endl;

	// 一键调用我们封装好的高级注入 API
	if (!InjectFromFile(PID, dllPath.c_str())) {
		std::wcout << L"\n[DLLinject] X Injection failed. Please check the logs." << std::endl;
		system("pause");
		return -3;
	}

	std::wcout << L"\n[DLLinject] >>> Injection successful! OK. <<<" << std::endl;
	system("pause");
	return 0;
}