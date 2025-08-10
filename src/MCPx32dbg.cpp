#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN

// 32-bit specific plugin implementation for x32dbg
// This file mirrors MCPx64dbg.cpp but adapts naming and RIP/EIP usage

#include <Windows.h>
#include "pluginsdk/bridgemain.h"
#include "pluginsdk/_plugins.h"
#include "pluginsdk/_scriptapi_module.h"
#include "pluginsdk/_scriptapi_memory.h"
#include "pluginsdk/_scriptapi_register.h"
#include "pluginsdk/_scriptapi_debug.h"
#include "pluginsdk/_scriptapi_assembler.h"
#include "pluginsdk/_scriptapi_comment.h"
#include "pluginsdk/_scriptapi_label.h"
#include "pluginsdk/_scriptapi_bookmark.h"
#include "pluginsdk/_scriptapi_function.h"
#include "pluginsdk/_scriptapi_argument.h"
#include "pluginsdk/_scriptapi_symbol.h"
#include "pluginsdk/_scriptapi_stack.h"
#include "pluginsdk/_scriptapi_pattern.h"
#include "pluginsdk/_scriptapi_flag.h"
#include "pluginsdk/_scriptapi_gui.h"
#include "pluginsdk/_scriptapi_misc.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <mutex>
#include <thread>
#include <algorithm>
#include <memory>
#include <fstream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")

#define PLUGIN_NAME "x32dbg HTTP Server"
#define PLUGIN_VERSION 1

#define DEFAULT_PORT 8888
#define MAX_REQUEST_SIZE 8192

int g_pluginHandle32;
HANDLE g_httpServerThread32 = NULL;
bool g_httpServerRunning32 = false;
int g_httpPort32 = DEFAULT_PORT;
std::mutex g_httpMutex32;
SOCKET g_serverSocket32 = INVALID_SOCKET;

// Forward declarations (32-bit variants)
bool startHttpServer32();
void stopHttpServer32();
DWORD WINAPI HttpServerThread32(LPVOID lpParam);
std::string readHttpRequest32(SOCKET clientSocket);
void sendHttpResponse32(SOCKET clientSocket, int statusCode, const std::string& contentType, const std::string& responseBody);
void parseHttpRequest32(const std::string& request, std::string& method, std::string& path, std::string& query, std::string& body);
std::unordered_map<std::string, std::string> parseQueryParams32(const std::string& query);
std::string urlDecode32(const std::string& str);

bool cbEnableHttpServer32(int argc, char* argv[]);
bool cbSetHttpPort32(int argc, char* argv[]);
void registerCommands32();

// Plugin init
bool pluginInit(PLUG_INITSTRUCT* initStruct) {
    initStruct->pluginVersion = PLUGIN_VERSION;
    initStruct->sdkVersion = PLUG_SDKVERSION;
    strncpy_s(initStruct->pluginName, PLUGIN_NAME, _TRUNCATE);
    g_pluginHandle32 = initStruct->pluginHandle;
    _plugin_logputs("x32dbg HTTP Server plugin loading...");
    registerCommands32();
    if (startHttpServer32()) {
        _plugin_logprintf("x32dbg HTTP Server started on port %d\n", g_httpPort32);
    } else {
        _plugin_logputs("Failed to start HTTP server (x32dbg)!");
    }
    _plugin_logputs("x32dbg HTTP Server plugin loaded!");
    return true;
}

void pluginStop() {
    _plugin_logputs("Stopping x32dbg HTTP Server...");
    stopHttpServer32();
    _plugin_logputs("x32dbg HTTP Server stopped.");
}

bool pluginSetup() { return true; }

extern "C" __declspec(dllexport) bool pluginit(PLUG_INITSTRUCT* initStruct) { return pluginInit(initStruct); }
extern "C" __declspec(dllexport) void plugstop() { pluginStop(); }
extern "C" __declspec(dllexport) void plugsetup(PLUG_SETUPSTRUCT* setupStruct) { pluginSetup(); }

// URL decode
std::string urlDecode32(const std::string& str) {
    std::string decoded;
    for (size_t i = 0; i < str.length(); ++i) {
        if (str[i] == '%' && i + 2 < str.length()) {
            int value; std::istringstream is(str.substr(i + 1, 2));
            if (is >> std::hex >> value) { decoded += static_cast<char>(value); i += 2; }
            else decoded += str[i];
        } else if (str[i] == '+') decoded += ' '; else decoded += str[i];
    }
    return decoded;
}

bool startHttpServer32() {
    std::lock_guard<std::mutex> lock(g_httpMutex32);
    if (g_httpServerRunning32) stopHttpServer32();
    g_httpServerThread32 = CreateThread(NULL, 0, HttpServerThread32, NULL, 0, NULL);
    if (!g_httpServerThread32) { _plugin_logputs("Failed to create HTTP server thread (x32dbg)"); return false; }
    g_httpServerRunning32 = true; return true;
}

void stopHttpServer32() {
    std::lock_guard<std::mutex> lock(g_httpMutex32);
    if (g_httpServerRunning32) {
        g_httpServerRunning32 = false;
        if (g_serverSocket32 != INVALID_SOCKET) { closesocket(g_serverSocket32); g_serverSocket32 = INVALID_SOCKET; }
        if (g_httpServerThread32) { WaitForSingleObject(g_httpServerThread32, 1000); CloseHandle(g_httpServerThread32); g_httpServerThread32 = NULL; }
    }
}

DWORD WINAPI HttpServerThread32(LPVOID) {
    WSADATA wsaData; if (WSAStartup(MAKEWORD(2,2), &wsaData)) return 1;
    g_serverSocket32 = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (g_serverSocket32 == INVALID_SOCKET) { WSACleanup(); return 1; }
    sockaddr_in serverAddr{}; serverAddr.sin_family = AF_INET; serverAddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); serverAddr.sin_port = htons((u_short)g_httpPort32);
    if (bind(g_serverSocket32, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) { closesocket(g_serverSocket32); WSACleanup(); return 1; }
    if (listen(g_serverSocket32, SOMAXCONN) == SOCKET_ERROR) { closesocket(g_serverSocket32); WSACleanup(); return 1; }
    _plugin_logprintf("HTTP server (x32dbg) at http://localhost:%d/\n", g_httpPort32);
    u_long mode = 1; ioctlsocket(g_serverSocket32, FIONBIO, &mode);
    while (g_httpServerRunning32) {
        sockaddr_in clientAddr; int sz = sizeof(clientAddr);
        SOCKET clientSocket = accept(g_serverSocket32, (sockaddr*)&clientAddr, &sz);
        if (clientSocket == INVALID_SOCKET) { if (!g_httpServerRunning32) break; if (WSAGetLastError() != WSAEWOULDBLOCK) _plugin_logprintf("Accept error: %d\n", WSAGetLastError()); Sleep(100); continue; }
        std::string request = readHttpRequest32(clientSocket);
        if (!request.empty()) {
            std::string method, path, query, body; parseHttpRequest32(request, method, path, query, body);
            std::unordered_map<std::string,std::string> qp = parseQueryParams32(query);
            try {
                if (path == "/ExecCommand") {
                    std::string cmd = qp["cmd"]; if (cmd.empty() && !body.empty()) cmd = body; if (cmd.empty()) { sendHttpResponse32(clientSocket,400,"text/plain","Missing command parameter"); goto close_client; }
                    char tempPath[MAX_PATH]; GetTempPathA(MAX_PATH, tempPath); std::string logFile = std::string(tempPath)+"x32dbg_cmd_"+std::to_string(GetTickCount())+".log";
                    std::string redirectCmd = "LogRedirect \""+logFile+"\""; DbgCmdExecDirect(redirectCmd.c_str()); Sleep(50); DbgCmdExecDirect("ClearLog"); Sleep(50); bool success = DbgCmdExecDirect(cmd.c_str()); Sleep(200); DbgCmdExecDirect("LogRedirectStop"); Sleep(100);
                    std::string output; for (int r=0;r<5;r++){ std::ifstream f(logFile, std::ios::binary); if(f.is_open()){ std::stringstream buf; buf<<f.rdbuf(); output=buf.str(); if(!output.empty()) break; } Sleep(100);} DeleteFileA(logFile.c_str());
                    if (!output.empty()) {
                        auto scrub=[&](const char* marker){ size_t p=0; while((p=output.find(marker,p))!=std::string::npos){ size_t e=output.find('\n',p); if(e!=std::string::npos) output.erase(p,e-p+1); else { output.erase(p); break; } } }; scrub("Log will be redirected to"); scrub("Log redirection stopped"); scrub("Log cleared");
                        if(!output.empty()){ output.erase(0, output.find_first_not_of(" \t\n\r")); if(!output.empty()) output.erase(output.find_last_not_of(" \t\n\r")+1); }
                    }
                    std::string resp; if(success) resp = output.empty()?"Command executed successfully (no output captured)":output; else resp = output.empty()?"Command execution failed":"Command failed:\n"+output; sendHttpResponse32(clientSocket, success?200:500, "text/plain", resp);
                }
                else if (path == "/IsDebugActive") { bool run=DbgIsRunning(); std::stringstream ss; ss<<"{\"isRunning\":"<<(run?"true":"false")<<"}"; sendHttpResponse32(clientSocket,200,"application/json",ss.str()); }
                else if (path == "/Is_Debugging") { bool dbg=DbgIsDebugging(); std::stringstream ss; ss<<"{\"isDebugging\":"<<(dbg?"true":"false")<<"}"; sendHttpResponse32(clientSocket,200,"application/json",ss.str()); }
                else if (path == "/Register/Get") {
                    std::string rn = qp["register"]; if(rn.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing register parameter"); goto close_client; }
                    Script::Register::RegisterEnum reg; if(rn=="EAX"||rn=="eax") reg=Script::Register::EAX; else if(rn=="EBX"||rn=="ebx") reg=Script::Register::EBX; else if(rn=="ECX"||rn=="ecx") reg=Script::Register::ECX; else if(rn=="EDX"||rn=="edx") reg=Script::Register::EDX; else if(rn=="ESI"||rn=="esi") reg=Script::Register::ESI; else if(rn=="EDI"||rn=="edi") reg=Script::Register::EDI; else if(rn=="EBP"||rn=="ebp") reg=Script::Register::EBP; else if(rn=="ESP"||rn=="esp") reg=Script::Register::ESP; else if(rn=="EIP"||rn=="eip") reg=Script::Register::EIP; else { sendHttpResponse32(clientSocket,400,"text/plain","Unknown register"); goto close_client; }
                    duint v=Script::Register::Get(reg); std::stringstream ss; ss<<"0x"<<std::hex<<v; sendHttpResponse32(clientSocket,200,"text/plain",ss.str());
                }
                else if (path == "/Register/Set") {
                    std::string rn=qp["register"], vs=qp["value"]; if(rn.empty()||vs.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing register or value parameter"); goto close_client; }
                    Script::Register::RegisterEnum reg; if(rn=="EAX"||rn=="eax") reg=Script::Register::EAX; else if(rn=="EBX"||rn=="ebx") reg=Script::Register::EBX; else if(rn=="ECX"||rn=="ecx") reg=Script::Register::ECX; else if(rn=="EDX"||rn=="edx") reg=Script::Register::EDX; else if(rn=="ESI"||rn=="esi") reg=Script::Register::ESI; else if(rn=="EDI"||rn=="edi") reg=Script::Register::EDI; else if(rn=="EBP"||rn=="ebp") reg=Script::Register::EBP; else if(rn=="ESP"||rn=="esp") reg=Script::Register::ESP; else if(rn=="EIP"||rn=="eip") reg=Script::Register::EIP; else { sendHttpResponse32(clientSocket,400,"text/plain","Unknown register"); goto close_client; }
                    duint val=0; try { if(vs.rfind("0x",0)==0) val=std::stoull(vs.substr(2),nullptr,16); else val=std::stoull(vs,nullptr,16);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid value format"); goto close_client; }
                    bool ok=Script::Register::Set(reg,val); sendHttpResponse32(clientSocket, ok?200:500, "text/plain", ok?"Register set successfully":"Failed to set register");
                }
                // Memory Read/Write/IsValidPtr/GetProtect
                else if (path == "/Memory/Read") {
                    std::string a=qp["addr"], s=qp["size"]; if(a.empty()||s.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing address or size"); goto close_client; }
                    duint addr=0; duint size=0; try { if(a.rfind("0x",0)==0) addr=std::stoull(a.substr(2),nullptr,16); else addr=std::stoull(a,nullptr,16); size=std::stoull(s,nullptr,10);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid address or size format"); goto close_client; }
                    if(size>1024*1024){ sendHttpResponse32(clientSocket,400,"text/plain","Size too large"); goto close_client; }
                    std::vector<unsigned char> buf(size); duint read=0; if(!Script::Memory::Read(addr,buf.data(),size,&read)){ sendHttpResponse32(clientSocket,500,"text/plain","Failed to read memory"); goto close_client; }
                    std::stringstream ss; for(duint i=0;i<read;i++) ss<<std::setw(2)<<std::setfill('0')<<std::hex<<(int)buf[i]; sendHttpResponse32(clientSocket,200,"text/plain",ss.str());
                }
                else if (path == "/Memory/Write") {
                    std::string a=qp["addr"], d = !body.empty()?body:qp["data"]; if(a.empty()||d.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing address or data"); goto close_client; }
                    duint addr=0; try { if(a.rfind("0x",0)==0) addr=std::stoull(a.substr(2),nullptr,16); else addr=std::stoull(a,nullptr,16);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid address format"); goto close_client; }
                    std::vector<unsigned char> buf; for(size_t i=0;i<d.length();i+=2){ if(i+1>=d.length()) break; try { unsigned char b=(unsigned char)std::stoi(d.substr(i,2),nullptr,16); buf.push_back(b);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid data format"); goto close_client; }}
                    duint written=0; bool ok=Script::Memory::Write(addr,buf.data(),buf.size(),&written); sendHttpResponse32(clientSocket, ok?200:500, "text/plain", ok?"Memory written successfully":"Failed to write memory");
                }
                else if (path == "/Memory/IsValidPtr") { std::string a=qp["addr"]; if(a.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing address parameter"); goto close_client; } duint addr=0; try { if(a.rfind("0x",0)==0) addr=std::stoull(a.substr(2),nullptr,16); else addr=std::stoull(a,nullptr,16);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid address format"); goto close_client; } bool v=Script::Memory::IsValidPtr(addr); sendHttpResponse32(clientSocket,200,"text/plain", v?"true":"false"); }
                else if (path == "/Memory/GetProtect") { std::string a=qp["addr"]; if(a.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing address parameter"); goto close_client; } duint addr=0; try { if(a.rfind("0x",0)==0) addr=std::stoull(a.substr(2),nullptr,16); else addr=std::stoull(a,nullptr,16);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid address format"); goto close_client; } unsigned int prot=Script::Memory::GetProtect(addr); std::stringstream ss; ss<<"0x"<<std::hex<<prot; sendHttpResponse32(clientSocket,200,"text/plain",ss.str()); }
                // Debug API
                else if (path == "/Debug/Run") { Script::Debug::Run(); sendHttpResponse32(clientSocket,200,"text/plain","Debug run executed"); }
                else if (path == "/Debug/Pause") { Script::Debug::Pause(); sendHttpResponse32(clientSocket,200,"text/plain","Debug pause executed"); }
                else if (path == "/Debug/Stop") { Script::Debug::Stop(); sendHttpResponse32(clientSocket,200,"text/plain","Debug stop executed"); }
                else if (path == "/Debug/StepIn") { Script::Debug::StepIn(); sendHttpResponse32(clientSocket,200,"text/plain","Step in executed"); }
                else if (path == "/Debug/StepOver") { Script::Debug::StepOver(); sendHttpResponse32(clientSocket,200,"text/plain","Step over executed"); }
                else if (path == "/Debug/StepOut") { Script::Debug::StepOut(); sendHttpResponse32(clientSocket,200,"text/plain","Step out executed"); }
                else if (path == "/Debug/SetBreakpoint") { std::string a=qp["addr"]; if(a.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing address parameter"); goto close_client; } duint addr=0; try { if(a.rfind("0x",0)==0) addr=std::stoull(a.substr(2),nullptr,16); else addr=std::stoull(a,nullptr,16);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid address format"); goto close_client; } bool ok=Script::Debug::SetBreakpoint(addr); sendHttpResponse32(clientSocket, ok?200:500, "text/plain", ok?"Breakpoint set successfully":"Failed to set breakpoint"); }
                else if (path == "/Debug/DeleteBreakpoint") { std::string a=qp["addr"]; if(a.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing address parameter"); goto close_client; } duint addr=0; try { if(a.rfind("0x",0)==0) addr=std::stoull(a.substr(2),nullptr,16); else addr=std::stoull(a,nullptr,16);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid address format"); goto close_client; } bool ok=Script::Debug::DeleteBreakpoint(addr); sendHttpResponse32(clientSocket, ok?200:500, "text/plain", ok?"Breakpoint deleted successfully":"Failed to delete breakpoint"); }
                // Disasm endpoints (use EIP instead of RIP)
                else if (path == "/Disasm/GetInstruction") { std::string a=qp["addr"]; if(a.empty()){ sendHttpResponse32(clientSocket,400,"text/plain","Missing address parameter"); goto close_client; } duint addr=0; try { if(a.rfind("0x",0)==0) addr=std::stoull(a.substr(2),nullptr,16); else addr=std::stoull(a,nullptr,16);} catch(...) { sendHttpResponse32(clientSocket,400,"text/plain","Invalid address format"); goto close_client; } DISASM_INSTR instr; DbgDisasmAt(addr,&instr); std::stringstream ss; ss<<"{\"address\":\"0x"<<std::hex<<addr<<"\",\"instruction\":\""<<instr.instruction<<"\",\"size\":"<<std::dec<<instr.instr_size<<"}"; sendHttpResponse32(clientSocket,200,"application/json",ss.str()); }
                else if (path == "/Disasm/GetInstructionAtRIP") { duint eip = Script::Register::Get(Script::Register::EIP); DISASM_INSTR instr; DbgDisasmAt(eip,&instr); std::stringstream ss; ss<<"{\"eip\":\"0x"<<std::hex<<eip<<"\",\"instruction\":\""<<instr.instruction<<"\",\"size\":"<<std::dec<<instr.instr_size<<"}"; sendHttpResponse32(clientSocket,200,"application/json",ss.str()); }
                else if (path == "/Disasm/StepInWithDisasm") { Script::Debug::StepIn(); duint eip = Script::Register::Get(Script::Register::EIP); DISASM_INSTR instr; DbgDisasmAt(eip,&instr); std::stringstream ss; ss<<"{\"step_result\":\"Step in executed\",\"eip\":\"0x"<<std::hex<<eip<<"\",\"instruction\":\""<<instr.instruction<<"\",\"size\":"<<std::dec<<instr.instr_size<<"}"; sendHttpResponse32(clientSocket,200,"application/json",ss.str()); }
                else { sendHttpResponse32(clientSocket,404,"text/plain","Not Found"); }
            } catch(const std::exception& ex) { sendHttpResponse32(clientSocket,500,"text/plain",std::string("Internal Server Error: ")+ex.what()); }
        }
close_client:
        closesocket(clientSocket);
    }
    if (g_serverSocket32 != INVALID_SOCKET) { closesocket(g_serverSocket32); g_serverSocket32 = INVALID_SOCKET; }
    WSACleanup(); return 0;
}

std::string readHttpRequest32(SOCKET clientSocket) {
    std::string request; char buffer[MAX_REQUEST_SIZE]; u_long mode=0; ioctlsocket(clientSocket,FIONBIO,&mode); int br = recv(clientSocket, buffer, sizeof(buffer)-1, 0); if (br>0){ buffer[br]='\0'; request=buffer; } return request; }

void parseHttpRequest32(const std::string& request, std::string& method, std::string& path, std::string& query, std::string& body) {
    size_t firstLineEnd = request.find("\r\n"); if(firstLineEnd==std::string::npos) return; std::string requestLine = request.substr(0, firstLineEnd);
    size_t methodEnd = requestLine.find(' '); if(methodEnd==std::string::npos) return; method = requestLine.substr(0, methodEnd);
    size_t urlEnd = requestLine.find(' ', methodEnd+1); if(urlEnd==std::string::npos) return; std::string url = requestLine.substr(methodEnd+1, urlEnd-methodEnd-1);
    size_t q = url.find('?'); if(q!=std::string::npos){ path=url.substr(0,q); query=url.substr(q+1);} else { path=url; query=""; }
    size_t headersEnd = request.find("\r\n\r\n"); if(headersEnd==std::string::npos) return; body = request.substr(headersEnd+4);
}

void sendHttpResponse32(SOCKET clientSocket, int statusCode, const std::string& contentType, const std::string& responseBody) {
    std::string statusText; switch(statusCode){ case 200: statusText="OK"; break; case 404: statusText="Not Found"; break; case 500: statusText="Internal Server Error"; break; default: statusText="Unknown"; }
    std::stringstream response; response<<"HTTP/1.1 "<<statusCode<<" "<<statusText<<"\r\n"; response<<"Content-Type: "<<contentType<<"\r\n"; response<<"Content-Length: "<<responseBody.length()<<"\r\n"; response<<"Connection: close\r\n\r\n"; response<<responseBody; std::string rs=response.str(); send(clientSocket, rs.c_str(), (int)rs.length(), 0);
}

std::unordered_map<std::string,std::string> parseQueryParams32(const std::string& query) {
    std::unordered_map<std::string,std::string> params; size_t pos=0; while(pos<query.length()){ size_t next=query.find('&',pos); if(next==std::string::npos) next=query.length(); std::string pair=query.substr(pos,next-pos); size_t eq=pair.find('='); if(eq!=std::string::npos){ params[pair.substr(0,eq)] = pair.substr(eq+1); } pos=next+1; } return params; }

bool cbEnableHttpServer32(int, char**) { if (g_httpServerRunning32){ _plugin_logputs("Stopping HTTP server (x32dbg)..."); stopHttpServer32(); _plugin_logputs("HTTP server stopped"); } else { _plugin_logputs("Starting HTTP server (x32dbg)..."); if(startHttpServer32()) _plugin_logprintf("HTTP server started on port %d\n", g_httpPort32); else _plugin_logputs("Failed to start HTTP server"); } return true; }

bool cbSetHttpPort32(int argc, char* argv[]) { if(argc<2){ _plugin_logputs("Usage: httpport [port_number]"); return false; } int port=0; try { port=std::stoi(argv[1]); } catch(...) { _plugin_logputs("Invalid port number"); return false; } if(port<=0||port>65535){ _plugin_logputs("Port number must be between 1 and 65535"); return false; } g_httpPort32=port; if(g_httpServerRunning32){ _plugin_logputs("Restarting HTTP server with new port..."); stopHttpServer32(); if(startHttpServer32()) _plugin_logprintf("HTTP server restarted on port %d\n", g_httpPort32); else _plugin_logputs("Failed to restart HTTP server"); } else { _plugin_logprintf("HTTP port set to %d\n", g_httpPort32); } return true; }

void registerCommands32() { _plugin_registercommand(g_pluginHandle32, "httpserver", cbEnableHttpServer32, "Toggle HTTP server on/off"); _plugin_registercommand(g_pluginHandle32, "httpport", cbSetHttpPort32, "Set HTTP server port"); }
