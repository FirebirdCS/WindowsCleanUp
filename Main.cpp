#include "Main.h"

using namespace ProyectoWindowsCleanUp;

[STAThreadAttribute]

int main(array<System::String^>^ args) {
	Application::EnableVisualStyles();
	Application::SetCompatibleTextRenderingDefault(false);
	Application::Run(gcnew Main());

	return 0;
}