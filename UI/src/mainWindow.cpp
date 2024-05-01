
#include "imgui/imgui.h"

// System includes
#include <ctype.h>          // toupper
#include <d3d11.h>
#include <inttypes.h>       // PRId64/PRIu64, not avail in some MinGW headers.
#include <limits.h>         // INT_MIN, INT_MAX
#include <math.h>           // sqrtf, powf, cosf, sinf, floorf, ceilf
#include <stdint.h>         // intptr_t
#include <stdio.h>          // vsnprintf, sscanf, printf
#include <stdlib.h>         // NULL, malloc, free, atoi

#include <iostream>
#include <windows.h>

#include "../memory.h"
#include "../pipe.h"
#include <string>



#include "Aclapi.h"
#include "sddl.h"
#include "windows.h"

#include <atlbase.h>
#include <Shlobj.h>


#include <iostream>
#include <vector>
#include <ctime>
#include <iomanip>
#include <sstream> 

struct logmsg {
    std::time_t timestamp;
    std::string text;

};


static std::vector<logmsg> logmsgArray;

static constexpr int MAX_MESSAGES = 100;

static auto pipe = Pipe("Marceline");
static auto _hPipe = pipe.GetPipeHandle();
static auto mem = Memory("_Game_UWP_x86.exe");



static std::string timeToString(std::time_t timestamp) {
    std::tm timeinfo;
    if (localtime_s(&timeinfo, &timestamp) != 0) {
        return ""; // Handle error
    }

    // Format time as string
    char buffer[20]; // Sufficient size for the format "%Y-%m-%d %H:%M:%S"
    if (strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &timeinfo) == 0) {
        return ""; // Handle error
    }
    return std::string(buffer);
}


static char* ConvertDWORDtoChar(DWORD value) {
    char buffer[20]; // Sufficient size to hold DWORD as string
    sprintf_s(buffer, "%lu", value);
    char* result = new char[strlen(buffer) + 1]; // +1 for null terminator
    strcpy_s(result, strlen(buffer) + 1, buffer);
    return result;
}





static void ShowMainWindow() {



    // Demonstrate the various window flags. Typically you would just use the default!
    static bool no_titlebar = true;
    static bool no_scrollbar = false;
    static bool no_menu = true;
    static bool no_move = true;
    static bool no_resize = true;
    static bool no_collapse = true;
    static bool no_close = true;
    static bool no_nav = true;
    static bool no_background = false;
    static bool no_bring_to_front = false;
    static bool unsaved_document = false;

    ImGuiWindowFlags window_flags = 0;
    if (no_titlebar)        window_flags |= ImGuiWindowFlags_NoTitleBar;
    if (no_scrollbar)       window_flags |= ImGuiWindowFlags_NoScrollbar;
    if (!no_menu)           window_flags |= ImGuiWindowFlags_MenuBar;
    if (no_move)            window_flags |= ImGuiWindowFlags_NoMove;
    if (no_resize)          window_flags |= ImGuiWindowFlags_NoResize;
    if (no_collapse)        window_flags |= ImGuiWindowFlags_NoCollapse;
    if (no_nav)             window_flags |= ImGuiWindowFlags_NoNav;
    if (no_background)      window_flags |= ImGuiWindowFlags_NoBackground;
    if (no_bring_to_front)  window_flags |= ImGuiWindowFlags_NoBringToFrontOnFocus;
    if (unsaved_document)   window_flags |= ImGuiWindowFlags_UnsavedDocument;

    const ImGuiViewport* main_viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(ImVec2( 0, 0), ImGuiCond_None);
    ImGui::SetNextWindowSize(ImVec2(604, 404), ImGuiCond_None);
    ImGuiIO& io = ImGui::GetIO(); (void)io;

    ImGui::Begin("main",nullptr, window_flags);

    ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);
    ImGui::Text(  ConvertDWORDtoChar(mem.GetProcessId()));



  if (pipe.GetPipeConnected()) {
        ImGui::Text("connected.");

        ImGui::SeparatorText("log");

        static ImGuiChildFlags child_flags = ImGuiChildFlags_Border | ImGuiChildFlags_ResizeX | ImGuiChildFlags_ResizeY;

        ImGui::BeginChild("Red", ImVec2(200, 100), child_flags, ImGuiWindowFlags_None);


        if (pipe.piReadMessageAsync()) {
            // Get the current time

            // Get the message from the pipe buffer
            std::string message(pipe.GetPipeBuffer());

            // Add the current time and message to the messages array

            
            logmsgArray.insert(logmsgArray.end(), logmsg(std::time(0), message));

        for (const auto& pair : logmsgArray) {

            ImGui::Text("Timestamp: %s, Text: %s", timeToString( pair.timestamp), pair.text.c_str());
        }
        ImGui::EndChild();

    }
    else { ImGui::Text("Waiting for client connection..."); }



    //if (val1)
    //    ImGui::Text(val1);


    //ImGui::Text(val );
    ImGui::End();


	return;
}
