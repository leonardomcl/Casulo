unit reswindows;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, ComCtrls, ExtCtrls,
  StdCtrls, Buttons, WindowsVersionInfo, CasuloCommon, CasuloConfig;

type

  TFResWindows = class(TForm)
    BtnRandInfo: TButton;
    BtnChangeIcon: TButton;
    Button1: TButton;
    EdtCompanyName: TLabeledEdit;
    EdtFileDescription: TLabeledEdit;
    EdtFileVersion: TLabeledEdit;
    EdtInternalName: TLabeledEdit;
    EdtOriginalFilename: TLabeledEdit;
    EdtProductName: TLabeledEdit;
    EdtLegalCopyright: TLabeledEdit;
    EdtProductVersion: TLabeledEdit;
    GroupBox1: TGroupBox;
    ImgDefaultIcon: TImage;
    OpenDialog1: TOpenDialog;
    PageControl1: TPageControl;
    StatusBar1: TStatusBar;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;

    procedure BtnChangeIconClick(Sender: TObject);
    procedure BtnRandInfoClick(Sender: TObject);
    procedure Button1Click(Sender: TObject);

    procedure FormShow(Sender: TObject);

  private

  public
    procedure FillInputs(Info: TWindowsVersionInfo);
    function GetResInputs(): TStringList;
  end;


const

  ICON_RELATIVE_PATH: string = 'stub_windows/assets/icon.ico';

var
  FResWindows: TFResWindows;

implementation

{$R *.lfm}

function IconPath: string; inline;
begin
  Result := ProjectPath(ICON_RELATIVE_PATH);
end;

function TFResWindows.GetResInputs() : TStringList;
var
  ResItems: TStringList;
begin

  ResItems := TStringList.Create;

  ResItems.AddPair('CompanyName', EdtCompanyName.Text);
  ResItems.AddPair('FileDescription', EdtFileDescription.Text);
  ResItems.AddPair('ProductName', EdtProductName.Text);
  ResItems.AddPair('LegalCopyright', EdtLegalCopyright.Text);
  ResItems.AddPair('OriginalFilename', EdtOriginalFilename.Text);
  ResItems.AddPair('InternalName', EdtInternalName.Text);
   ResItems.AddPair('ProductVersion',  EdtProductVersion.Text );
  ResItems.AddPair('FileVersion',  EdtFileVersion.Text );


  Result := ResItems;
end;


procedure TFResWindows.FillInputs(Info: TWindowsVersionInfo);
begin
  EdtCompanyName.Text := Info.CompanyName;
  EdtFileDescription.Text := Info.FileDescription;
  EdtProductName.Text := Info.ProductName;
  EdtLegalCopyright.Text := Info.LegalCopyright;
  EdtOriginalFilename.Text := Info.OriginalFilename;
  EdtInternalName.Text := Info.InternalName;
  EdtProductVersion.Text := Info.ProductVersion;
  EdtFileVersion.Text := Info.FileVersion;
end;

procedure TFResWindows.BtnRandInfoClick(Sender: TObject);
var
  Info: TWindowsVersionInfo;
begin
  Info := GenerateRandomVersionInfo;

  FillInputs(Info);

end;

procedure TFResWindows.Button1Click(Sender: TObject);
var
  Saida: string;
  Status: boolean;
  TempIcon: string;
begin
  if not FileExists(IconPath) then
  begin
    ShowMessage('Ícone não encontrado: ' + IconPath);
    Exit;
  end;

  TempIcon :=
    ChangeFileExt(IconPath, '') + '_optimized.ico';

  Status := ExecutarProcesso('magick', [IconPath + '[0]', '-resize',
    '32x32', '-strip', '-compress', 'Zip', '-define', 'png:compression-level=9',
    TempIcon], Saida);

  if not Status then
  begin
    ShowMessage(
      'Erro ao otimizar o ícone:' + LineEnding + Saida
      );
    Exit;
  end;

  if not FileExists(TempIcon) then
  begin
    ShowMessage('O ImageMagick não gerou o arquivo de saída.');
    Exit;
  end;

  { Troca o recurso original pela versão otimizada. }
  if not DeleteFile(IconPath) then
  begin
    ShowMessage('Não foi possível remover o ícone original.');
    Exit;
  end;

  if not RenameFile(TempIcon, IconPath) then
  begin
    ShowMessage('Não foi possível substituir o ícone original.');
    Exit;
  end;


  ImgDefaultIcon.Picture.LoadFromFile(IconPath);
  ShowMessage('Ícone otimizado com sucesso.');
end;

procedure TFResWindows.BtnChangeIconClick(Sender: TObject);
begin
  if OpenDialog1.Execute then
  begin

    ImgDefaultIcon.Picture.LoadFromFile(OpenDialog1.FileName);

    ImgDefaultIcon.Picture.SaveToFile(IconPath);

    if (FileExists(IconPath)) then
      ShowMessage('Novo ícone setado como default')
    else
    begin
      ShowMessage('Error ao setar novo ícone como default');
      ImgDefaultIcon.Picture.Clear;
    end;
  end;
end;


procedure TFResWindows.FormShow(Sender: TObject);
begin
  if (FileExists(IconPath)) then
  begin
    ImgDefaultIcon.Picture.LoadFromFile(IconPath);
  end;

end;

end.
