#pragma once
#include <Windows.h>
#include <msclr\marshal_cppstd.h>
#include <iostream>

namespace ProyectoWindowsCleanUp {

	using namespace System;
	using namespace System::ComponentModel;
	using namespace System::Collections;
	using namespace System::Windows::Forms;
	using namespace System::Data;
	using namespace System::Drawing;
	using namespace System::Diagnostics;
	using namespace msclr::interop;

	/// <summary>
	/// Resumen de Main
	/// </summary>
	public ref class Main : public System::Windows::Forms::Form
	{
	public:
		Main(void)
		{
			InitializeComponent();
			//
			//TODO: agregar código de constructor aquí
			//
		}

	protected:
		/// <summary>
		/// Limpiar los recursos que se estén usando.
		/// </summary>
		~Main()
		{
			if (components)
			{
				delete components;
			}
		}
	private: System::Windows::Forms::Button^ btn_Clean;

	protected:

	private:
		/// <summary>
		/// Variable del diseñador necesaria.
		/// </summary>
		System::ComponentModel::Container^ components;

#pragma region Windows Form Designer generated code
		/// <summary>
		/// Método necesario para admitir el Diseñador. No se puede modificar
		/// el contenido de este método con el editor de código.
		/// </summary>
		void InitializeComponent(void)
		{
			System::ComponentModel::ComponentResourceManager^ resources = (gcnew System::ComponentModel::ComponentResourceManager(Main::typeid));
			this->btn_Clean = (gcnew System::Windows::Forms::Button());
			this->SuspendLayout();
			// 
			// btn_Clean
			// 
			this->btn_Clean->Location = System::Drawing::Point(25, 103);
			this->btn_Clean->Name = L"btn_Clean";
			this->btn_Clean->Size = System::Drawing::Size(221, 74);
			this->btn_Clean->TabIndex = 0;
			this->btn_Clean->Text = L"Limpieza de servicios de tracking / Remover porgramas innecesarios";
			this->btn_Clean->UseVisualStyleBackColor = true;
			this->btn_Clean->Click += gcnew System::EventHandler(this, &Main::Clean_Click);
			// 
			// Main
			// 
			this->AutoScaleDimensions = System::Drawing::SizeF(8, 16);
			this->AutoScaleMode = System::Windows::Forms::AutoScaleMode::Font;
			this->BackColor = System::Drawing::Color::FromArgb(static_cast<System::Int32>(static_cast<System::Byte>(255)), static_cast<System::Int32>(static_cast<System::Byte>(255)),
				static_cast<System::Int32>(static_cast<System::Byte>(192)));
			this->BackgroundImage = (cli::safe_cast<System::Drawing::Image^>(resources->GetObject(L"$this.BackgroundImage")));
			this->ClientSize = System::Drawing::Size(902, 481);
			this->Controls->Add(this->btn_Clean);
			this->Icon = (cli::safe_cast<System::Drawing::Icon^>(resources->GetObject(L"$this.Icon")));
			this->Name = L"Main";
			this->Text = L"Windows CleanUp";
			this->Load += gcnew System::EventHandler(this, &Main::Main_Load);
			this->ResumeLayout(false);

		}
	private: System::Void Clean_Click(System::Object^ sender, System::EventArgs^ e) {
		String^ scriptPath = "LocationDisable.ps1";
		std::string scriptPathCpp = marshal_as<std::string>(scriptPath);
		Process^ powerShell = gcnew Process();
		powerShell->StartInfo->FileName = "powershell.exe";
		powerShell->StartInfo->Arguments = "-ExecutionPolicy Bypass -File " + scriptPath;
		powerShell->StartInfo->UseShellExecute = false;
		powerShell->StartInfo->RedirectStandardOutput = true;
		powerShell->Start();
		// Leer la salida del script
		String^ output = powerShell->StandardOutput->ReadToEnd();

		// Convertir la salida a una cadena de C++
		std::string outputCpp = marshal_as<std::string>(output);

		// Mostrar la salida en la consola
		std::cout << outputCpp << std::endl;

		// Mostrar una ventana de diálogo que indique que el script se ha ejecutado
		MessageBox::Show("El script se ha ejecutado correctamente", "Ejecución del script de PowerShell", MessageBoxButtons::OK, MessageBoxIcon::Information);
	}
#pragma endregion
	private: System::Void Main_Load(System::Object^ sender, System::EventArgs^ e) {
	}
	private: System::Void pictureBox1_Click(System::Object^ sender, System::EventArgs^ e) {
	}
};
}
