unit Principal;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, ComCtrls, StdCtrls,
  ExtCtrls, Menus, Buttons, Packer, CasuloLinuxPipeline, CasuloWindowsPipeline,
  Requeriments, reswindows, WindowsVersionInfo, compresscfg, cfgimgbasewin,
  chkzcfg, cfgrustcompileropt, cfgtargetlinux, About, LCLIntf;

type
  TFPrincipal = class;

  { O build roda fora da thread da interface e trabalha com uma cópia da configuração. }

  TBuildThread = class(TThread)
  private
    FOwner: TFPrincipal;
    FPlataforma: integer;
    FAlvoPath: string;
    FSaidaPath: string;

    procedure NotifyFinished;
  protected
    procedure Execute; override;
  public
    constructor Create(AOwner: TFPrincipal; APlataforma: integer;
      const AAlvoPath, ASaidaPath: string);
  end;


  { Encaminha mensagens da worker para a LCL pela thread principal. }

  TLogSynchronizer = class
  private
    FOwner: TFPrincipal;
    FMessage: string;
  public
    constructor Create(AOwner: TFPrincipal; const AMessage: string);
    procedure Execute;
  end;

  TFPrincipal = class(TForm)
    BtnConfigCompactWin1: TButton;
    BtnRustCmOpt: TButton;
    BtnConfigCompactWin: TButton;
    BtnImageBaseWin: TButton;
    BtnConfigRes: TButton;
    BtnChkzCfg: TButton;
    BtnRustCmOpt1: TButton;
    BtnLinuxTarget: TButton;
    Image1: TImage;
    MenuItem3: TMenuItem;
    MenuItem4: TMenuItem;
    MenuItem5: TMenuItem;
    OpenFile: TButton;
    BtnSave: TButton;
    EdtOpenFile: TEdit;
    EdtSaveFile: TEdit;
    GroupBox1: TGroupBox;
    GroupBox2: TGroupBox;
    MainMenu1: TMainMenu;
    MLog: TMemo;
    MenuItem1: TMenuItem;
    MenuItem2: TMenuItem;
    OpenDialog1: TOpenDialog;
    PageControl1: TPageControl;
    BtnCryptografar: TPanel;
    Panel2: TPanel;
    PopupMenu1: TPopupMenu;
    SaveDialog1: TSaveDialog;
    StatusBar1: TStatusBar;
    TabSheet1: TTabSheet;
    TabSheet2: TTabSheet;

    procedure BtnChkzCfgClick(Sender: TObject);
    procedure BtnImageBaseWinClick(Sender: TObject);
    procedure BtnConfigCompactWinClick(Sender: TObject);
    procedure BtnConfigResClick(Sender: TObject);
    procedure BtnConfigResoucesClick(Sender: TObject);
    procedure BtnCryptografarClick(Sender: TObject);
    procedure BtnLinuxTargetClick(Sender: TObject);
    procedure BtnRustCmOptClick(Sender: TObject);
    procedure BtnSaveClick(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure FormCreate(Sender: TObject);
    procedure MenuItem2Click(Sender: TObject);
    procedure MenuItem4Click(Sender: TObject);
    procedure MenuItem5Click(Sender: TObject);
    procedure OpenFileClick(Sender: TObject);
    procedure FormDropFiles(Sender: TObject; const FileNames: array of string);

  private
    FBuildRunning: boolean;
    FBuildThread: TBuildThread;

    FLastBuildOk: boolean;
    FLastBuildError: string;

    procedure LogMessage(const Msg: string);
    procedure DebugCallback(const Msg: string);

    procedure AbrirArquivoParaEmpacotar(const FileName: string);

    function EmpacotarExecutavelLinux(const AAlvoPath, ASaidaPath: string;
      out Erro: string): boolean;


    function EmpacotarExecutavelWindows(
      const AAlvoPath, ASaidaPath: string; out Erro: string): boolean;

    function CheckFileDestination: integer;
    procedure TestarVersionInfo(const FileName: string);
    procedure CheckRequeriments;

    procedure SetBuildControlsEnabled(AEnabled: boolean);
    procedure UpdateBuildButtonState;
    procedure BuildFinished;
  public
  end;


const
  DESTINATION_UNKNOWN = 0;
  DESTINATION_WINDOWS = 1;
  DESTINATION_LINUX = 2;


var
  FPrincipal: TFPrincipal;

  AlvoPath: string;
  SaidaPath: string;
  DestinationSo: integer;


implementation

{$R *.lfm}

constructor TLogSynchronizer.Create(AOwner: TFPrincipal; const AMessage: string);
begin
  inherited Create;
  FOwner := AOwner;
  FMessage := AMessage;
end;


procedure TLogSynchronizer.Execute;
begin
  if Assigned(FOwner) and Assigned(FOwner.MLog) then
  begin
    FOwner.MLog.Lines.Add(FMessage);

    
    FOwner.MLog.SelStart := Length(FOwner.MLog.Text);
  end;
end;

constructor TBuildThread.Create(AOwner: TFPrincipal; APlataforma: integer;
  const AAlvoPath, ASaidaPath: string);
begin
  inherited Create(True);

  FreeOnTerminate := True;

  FOwner := AOwner;
  FPlataforma := APlataforma;

  
  FAlvoPath := AAlvoPath;
  FSaidaPath := ASaidaPath;
end;


procedure TBuildThread.Execute;
var
  Ok: boolean;
  Erro: string;
begin
  Ok := False;
  Erro := '';

  try
    case FPlataforma of

      DESTINATION_WINDOWS:
        Ok := FOwner.EmpacotarExecutavelWindows(FAlvoPath, FSaidaPath, Erro);

      DESTINATION_LINUX:
        Ok := FOwner.EmpacotarExecutavelLinux(FAlvoPath, FSaidaPath, Erro);

      else
        Erro := 'Plataforma de destino inválida.';
    end;

  except
    on E: Exception do
    begin
      Ok := False;
      Erro := E.ClassName + ': ' + E.Message;
    end;
  end;

  
  if Assigned(FOwner) then
  begin
    FOwner.FLastBuildOk := Ok;
    FOwner.FLastBuildError := Erro;

    { Finaliza o estado da UI antes de liberar a worker. }
    Synchronize(@NotifyFinished);
  end;
end;


procedure TBuildThread.NotifyFinished;
begin
  if Assigned(FOwner) then
    FOwner.BuildFinished;
end;

procedure TFPrincipal.TestarVersionInfo(const FileName: string);
var
  Info: TWindowsVersionInfo;
begin
  if ExtractWindowsVersionInfo(FileName, Info) then
  begin
    LogMessage('CompanyName: ' + Info.CompanyName);
    LogMessage('FileDescription: ' + Info.FileDescription);
    LogMessage('ProductName: ' + Info.ProductName);
    LogMessage('LegalCopyright: ' + Info.LegalCopyright);
    LogMessage('OriginalFilename: ' + Info.OriginalFilename);
    LogMessage('InternalName: ' + Info.InternalName);
    LogMessage('ProductVersion: ' + Info.ProductVersion);
    LogMessage('FileVersion: ' + Info.FileVersion);

    FResWindows.FillInputs(Info);
  end
  else
    LogMessage('O executável não possui VERSIONINFO válido.');
end;


function DetectDestinationSO(const FileName: string): integer;
var
  Stream: TFileStream;
  Header: array[0..63] of byte;
  PESignature: array[0..3] of byte;
  PEOffset: longword;
begin
  Result := DESTINATION_UNKNOWN;

  if not FileExists(FileName) then
    Exit;

  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);

  try
    
    if Stream.Size < 64 then
      Exit;

    FillChar(Header, SizeOf(Header), 0);

    Stream.Position := 0;
    Stream.ReadBuffer(Header, SizeOf(Header));

    
    if (Header[0] = $7F) and (Header[1] = Ord('E')) and
      (Header[2] = Ord('L')) and (Header[3] = Ord('F')) then
    begin
      Result := DESTINATION_LINUX;
      Exit;
    end;

    
    if (Header[0] <> Ord('M')) or (Header[1] <> Ord('Z')) then
      Exit;

    
    PEOffset :=
      longword(Header[$3C]) or (longword(Header[$3D]) shl 8) or
      (longword(Header[$3E]) shl 16) or (longword(Header[$3F]) shl 24);

    if PEOffset > longword(Stream.Size - 4) then
      Exit;

    Stream.Position := PEOffset;
    Stream.ReadBuffer(PESignature, SizeOf(PESignature));

    
    if (PESignature[0] = Ord('P')) and (PESignature[1] = Ord('E')) and
      (PESignature[2] = $00) and (PESignature[3] = $00) then
    begin
      Result := DESTINATION_WINDOWS;
      Exit;
    end;

  finally
    Stream.Free;
  end;
end;


function TFPrincipal.CheckFileDestination: integer;
begin
  DestinationSo := DetectDestinationSO(AlvoPath);

  case DestinationSo of

    DESTINATION_WINDOWS:
      LogMessage('Arquivo detectado: Windows PE');

    DESTINATION_LINUX:
      LogMessage('Arquivo detectado: Linux ELF');

    else
    begin
      LogMessage('Formato de executável não reconhecido.');
      DestinationSo := DESTINATION_UNKNOWN;
    end;
  end;

  Result := DestinationSo;
end;


procedure TFPrincipal.LogMessage(const Msg: string);
var
  Sync: TLogSynchronizer;
begin
  if TThread.CurrentThread.ThreadID = MainThreadID then
  begin
    MLog.Lines.Add(Msg);
    MLog.SelStart := Length(MLog.Text);
    Exit;
  end;

  { Chamado pela worker; atualizações da LCL passam pelo sincronizador. }
  Sync := TLogSynchronizer.Create(Self, Msg);
  try
    TThread.Synchronize(TThread.CurrentThread, @Sync.Execute);
  finally
    Sync.Free;
  end;
end;


procedure TFPrincipal.DebugCallback(const Msg: string);
begin
  LogMessage('[DEBUG] ' + Msg);
end;


{ Rotinas usadas pela worker não devem abrir diálogos. }

function TFPrincipal.EmpacotarExecutavelLinux(
  const AAlvoPath, ASaidaPath: string; out Erro: string): boolean;
begin
  Erro := '';

  Result := EmpacotarLinux(AAlvoPath, ASaidaPath, @LogMessage, Erro);
end;


function TFPrincipal.EmpacotarExecutavelWindows(
  const AAlvoPath, ASaidaPath: string; out Erro: string): boolean;
begin
  Erro := '';

  Result := EmpacotarWindows(AAlvoPath, ASaidaPath, @LogMessage, Erro);
end;


procedure TFPrincipal.SetBuildControlsEnabled(AEnabled: boolean);
begin
  

  OpenFile.Enabled := AEnabled;
  BtnSave.Enabled := AEnabled and (AlvoPath <> '');

  BtnConfigCompactWin.Enabled := AEnabled;
  BtnConfigCompactWin1.Enabled := AEnabled;

  BtnRustCmOpt.Enabled := AEnabled;
  BtnRustCmOpt1.Enabled := AEnabled;

  BtnImageBaseWin.Enabled := AEnabled;
  BtnConfigRes.Enabled := AEnabled;
  BtnChkzCfg.Enabled := AEnabled;
  BtnLinuxTarget.Enabled := AEnabled;

  PageControl1.Enabled := AEnabled;

  
  if not AEnabled then
    BtnCryptografar.Enabled := False
  else
    UpdateBuildButtonState;
end;


procedure TFPrincipal.UpdateBuildButtonState;
begin
  BtnCryptografar.Enabled :=
    (not FBuildRunning) and (DestinationSo in [DESTINATION_WINDOWS,
    DESTINATION_LINUX]) and (Trim(AlvoPath) <> '') and FileExists(AlvoPath) and
    (Trim(SaidaPath) <> '');
end;


procedure TFPrincipal.BuildFinished;
begin
  

  FBuildRunning := False;
  FBuildThread := nil;

  SetBuildControlsEnabled(True);

  if FLastBuildOk then
  begin
    LogMessage('Build finalizado com sucesso.');

    ShowMessage('Arquivo empacotado com sucesso.');
  end
  else
  begin
    if Trim(FLastBuildError) = '' then
      FLastBuildError := 'Não foi possível empacotar o arquivo.';

    LogMessage('ERRO: ' + FLastBuildError);

    ShowMessage(
      'Erro ao empacotar:' + LineEnding + FLastBuildError
      );
  end;

  FLastBuildOk := False;
  FLastBuildError := '';
end;


procedure TFPrincipal.CheckRequeriments;
var
  Resultado: TRequirementsResult;
begin
  MLog.Clear;

  Resultado := GetRequeriments;

  try
    LogMessage('....Checking requeriments....');
    LogMessage('');

    LogMessage('.... Rust / compilação....');

    if Resultado['cargo'] then
      LogMessage('Cargo: OK')
    else
      LogMessage('Cargo: FAIL');

    if Resultado['rustc'] then
      LogMessage('Rustc: OK')
    else
      LogMessage('Rustc: FAIL');

    if Resultado['rustup'] then
      LogMessage('Rustup: OK')
    else
      LogMessage('Rustup: FAIL');

    if Resultado['cargo-xwin'] then
      LogMessage('Cargo-xwin: OK')
    else
      LogMessage('Cargo-xwin: FAIL');

    LogMessage('');
    LogMessage('.... Compressão....');

    if Resultado['brotli'] then
      LogMessage('Brotli: OK')
    else
      LogMessage('Brotli: FAIL');

    if Resultado['zstd'] then
      LogMessage('ZSTD: OK')
    else
      LogMessage('ZSTD: FAIL');

    LogMessage('');
    LogMessage('.... Utilitários....');

    if Resultado['strip'] then
      LogMessage('Strip: OK')
    else
      LogMessage('Strip: FAIL');

    if Resultado['magick'] then
      LogMessage('Magick: OK')
    else
      LogMessage('Magick: FAIL');

  finally
    Resultado.Free;
  end;
end;


procedure TFPrincipal.FormCreate(Sender: TObject);
begin
  FBuildRunning := False;
  FBuildThread := nil;
  FLastBuildOk := False;
  FLastBuildError := '';

  AlvoPath := '';
  SaidaPath := '';
  DestinationSo := DESTINATION_UNKNOWN;

  BtnCryptografar.Enabled := False;
  BtnSave.Enabled := False;

  TabSheet1.Enabled := False;
  TabSheet2.Enabled := False;

  Randomize;

  SetDebugCallback(@DebugCallback);

  CheckRequeriments;
end;

procedure TFPrincipal.AbrirArquivoParaEmpacotar(const FileName: string);
begin
  if FBuildRunning then
  begin
    ShowMessage('Existe um build em andamento.');
    Exit;
  end;

  if (FileName = '') or (not FileExists(FileName)) then
  begin
    ShowMessage('Arquivo inválido.');
    Exit;
  end;

  MLog.Clear;

  AlvoPath := ExpandFileName(FileName);
  EdtOpenFile.Text := AlvoPath;

  
  SaidaPath := '';
  EdtSaveFile.Clear;

  TabSheet1.Enabled := False;
  TabSheet2.Enabled := False;

  BtnSave.Enabled := False;
  BtnCryptografar.Enabled := False;

  LogMessage('Arquivo selecionado: ' + AlvoPath);

  case CheckFileDestination of

    DESTINATION_WINDOWS:
    begin
      TabSheet2.Enabled := True;
      PageControl1.TabIndex := 1;

      TestarVersionInfo(AlvoPath);
    end;

    DESTINATION_LINUX:
    begin
      TabSheet1.Enabled := True;
      PageControl1.TabIndex := 0;
    end;

    else
    begin
      AlvoPath := '';
      DestinationSo := DESTINATION_UNKNOWN;

      EdtOpenFile.Clear;

      ShowMessage(
        'O arquivo selecionado não é um executável ' +
        'Windows PE ou Linux ELF válido.'
        );

      UpdateBuildButtonState;
      Exit;
    end;

  end;

  BtnSave.Enabled := True;

  UpdateBuildButtonState;
end;

procedure TFPrincipal.FormDropFiles(Sender: TObject; const FileNames: array of string);
begin
  if Length(FileNames) = 0 then
    Exit;

  if Length(FileNames) > 1 then
  begin
    ShowMessage(
      'Arraste apenas um executável por vez.'
      );
    Exit;
  end;

  AbrirArquivoParaEmpacotar(FileNames[0]);
end;


procedure TFPrincipal.MenuItem2Click(Sender: TObject);
begin
  if FBuildRunning then
  begin
    ShowMessage('Aguarde o build atual terminar.');
    Exit;
  end;

  CheckRequeriments;
end;


procedure TFPrincipal.MenuItem4Click(Sender: TObject);
begin
  FrmAbout.ShowModal;
end;


procedure TFPrincipal.MenuItem5Click(Sender: TObject);
begin
  MLog.Clear;
end;


procedure TFPrincipal.BtnSaveClick(Sender: TObject);
begin
  if FBuildRunning then
    Exit;

  if not SaveDialog1.Execute then
    Exit;

  if Trim(SaveDialog1.FileName) = '' then
    Exit;

  SaidaPath := ExpandFileName(SaveDialog1.FileName);
  EdtSaveFile.Text := SaidaPath;

  LogMessage('Arquivo de saída: ' + SaidaPath);

  UpdateBuildButtonState;
end;


procedure TFPrincipal.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  { O formulário não pode ser fechado enquanto a worker estiver ativa. }
  if FBuildRunning then
  begin
    CloseAction := caNone;

    ShowMessage(
      'Existe um build em andamento.' + LineEnding +
      'Aguarde a conclusão antes de fechar o Casulo.'
      );

    Exit;
  end;
end;


procedure TFPrincipal.BtnCryptografarClick(Sender: TObject);
var
  Plataforma: integer;
  BuildAlvo: string;
  BuildSaida: string;
begin
  if FBuildRunning then
    Exit;

  
  if not (DestinationSo in [DESTINATION_WINDOWS, DESTINATION_LINUX]) then
  begin
    ShowMessage('Selecione um executável válido antes de prosseguir.');
    Exit;
  end;

  if (Trim(AlvoPath) = '') or (not FileExists(AlvoPath)) then
  begin
    ShowMessage('O arquivo de entrada não foi encontrado.');
    UpdateBuildButtonState;
    Exit;
  end;

  if Trim(SaidaPath) = '' then
  begin
    ShowMessage('Selecione o arquivo de saída antes de iniciar o build.');
    UpdateBuildButtonState;
    Exit;
  end;

  Plataforma := DestinationSo;

  
  BuildAlvo := ExpandFileName(AlvoPath);
  BuildSaida := ExpandFileName(SaidaPath);

  if SameFileName(BuildAlvo, BuildSaida) then
  begin
    ShowMessage('O arquivo de entrada e o arquivo de saída não podem ser iguais.');
    Exit;
  end;

  case Plataforma of
    DESTINATION_WINDOWS:
      LogMessage('Plataforma selecionada: Windows x64');

    DESTINATION_LINUX:
      LogMessage('Plataforma selecionada: Linux x86-64');
  end;

  LogMessage('Iniciando build em background...');

  FLastBuildOk := False;
  FLastBuildError := '';

  FBuildRunning := True;
  SetBuildControlsEnabled(False);

  try
    FBuildThread := TBuildThread.Create(Self, Plataforma, BuildAlvo,
      BuildSaida);

    FBuildThread.Start;

  except
    on E: Exception do
    begin
      FBuildThread := nil;
      FBuildRunning := False;

      SetBuildControlsEnabled(True);

      LogMessage('ERRO ao iniciar worker: ' + E.Message);

      ShowMessage(
        'Não foi possível iniciar o build:' + LineEnding + E.Message
        );
    end;
  end;
end;


procedure TFPrincipal.BtnLinuxTargetClick(Sender: TObject);
begin
  if not FBuildRunning then
    FTargetLinux.ShowModal;
end;


procedure TFPrincipal.BtnRustCmOptClick(Sender: TObject);
begin
  if not FBuildRunning then
    FRustCmpOpt.ShowModal;
end;


procedure TFPrincipal.BtnConfigResoucesClick(Sender: TObject);
begin
end;


procedure TFPrincipal.BtnConfigResClick(Sender: TObject);
begin
  if not FBuildRunning then
    FResWindows.ShowModal;
end;


procedure TFPrincipal.BtnConfigCompactWinClick(Sender: TObject);
begin
  if not FBuildRunning then
    FConfigCprsAlgo.ShowModal;
end;


procedure TFPrincipal.BtnImageBaseWinClick(Sender: TObject);
begin
  if not FBuildRunning then
    FImageBaseWin.ShowModal;
end;


procedure TFPrincipal.BtnChkzCfgClick(Sender: TObject);
begin
  if not FBuildRunning then
    FChkSizeCfg.ShowModal;
end;


procedure TFPrincipal.OpenFileClick(Sender: TObject);
begin
  if FBuildRunning then
    Exit;

  if not OpenDialog1.Execute then
    Exit;

  if OpenDialog1.FileName = '' then
    Exit;

  AbrirArquivoParaEmpacotar(
    OpenDialog1.FileName
    );
end;


end.
