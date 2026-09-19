unit cfgimgbasewin;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls,
  ExtCtrls, PEUtils, CasuloConfig;

type

  TFImageBaseWin = class(TForm)
    Label1: TLabel;
    EdtDeftImgBase: TLabeledEdit;
    RbImgBasTrue: TRadioButton;
    RbImgBasFalse: TRadioButton;
    BtnValidateImgBase: TToggleBox;
    ChangerndImageBase: TToggleBox;
    procedure BtnValidateImgBaseChange(Sender: TObject);
    procedure ChangerndImageBaseChange(Sender: TObject);
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
    procedure RbImgBasTrueClick(Sender: TObject);
    procedure RbImgBasFalseClick(Sender: TObject);
  private

  public

  end;

var
  FImageBaseWin: TFImageBaseWin;

implementation

{$R *.lfm}

function TryParseImageBase(const Text: string; out Value: QWord): boolean;
var
  S: string;
begin
  S := Trim(Text);

  if S = '' then
    Exit(False);

  
  if Copy(S, 1, 2) = '0x' then
    Delete(S, 1, 2)
  else if Copy(S, 1, 2) = '0X' then
    Delete(S, 1, 2)
  else if S[1] = '$' then
    Delete(S, 1, 1);

  
  Result := TryStrToQWord('$' + S, Value);
end;


procedure TFImageBaseWin.RbImgBasTrueClick(Sender: TObject);
begin
  EdtDeftImgBase.Enabled := False;
  ChangerndImageBase.Enabled := False;
  BtnValidateImgBase.Enabled := False;
end;

procedure TFImageBaseWin.ChangerndImageBaseChange(Sender: TObject);
begin
  EdtDeftImgBase.Text := '$' + IntToHex(GenerateRandomPE64ImageBase, 16);
end;

procedure TFImageBaseWin.BtnValidateImgBaseChange(Sender: TObject);
var
   ImageBase: QWord;
begin
  if not TryParseImageBase(EdtDeftImgBase.Text, ImageBase) then
  begin
    ShowMessage('ImageBase inválida.');
    exit;
  end;

  if (ImageBase and $FFFF) <> 0 then
  begin
    ShowMessage(
      'A ImageBase precisa estar alinhada em 64 KiB.' + LineEnding +
      'Os últimos 4 dígitos hexadecimais devem ser 0000.'
      );
     exit;
  end;

  ShowMessage('Imagebase válido!');

end;

procedure TFImageBaseWin.FormClose(Sender: TObject; var CloseAction: TCloseAction);
var
  ImageBase: QWord;
begin
  RANDOM_IMAGEBASE := RbImgBasTrue.Checked;

  if RbImgBasFalse.Checked then
  begin
    if not TryParseImageBase(EdtDeftImgBase.Text, ImageBase) then
    begin
      ShowMessage('ImageBase inválida.');

      CloseAction := caNone;
      Exit;
    end;

    { O linker espera ImageBase alinhada em 64 KiB. }
    if (ImageBase and $FFFF) <> 0 then
    begin
      ShowMessage(
        'A ImageBase precisa estar alinhada em 64 KiB.' + LineEnding +
        'Os últimos 4 dígitos hexadecimais devem ser 0000.'
        );

      CloseAction := caNone;
      Exit;
    end;

    DEFAULT_STUB_IMAGEBASE := ImageBase;
  end;

end;

procedure TFImageBaseWin.RbImgBasFalseClick(Sender: TObject);
begin
  EdtDeftImgBase.Enabled := True;
  ChangerndImageBase.Enabled := True;
  BtnValidateImgBase.Enabled := True;
end;

end.
