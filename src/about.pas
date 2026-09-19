unit about;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, ComCtrls, ExtCtrls,
  StdCtrls, Buttons, LCLIntf, CasuloConfig;

type

  TFrmAbout = class(TForm)
    BtnOpenGhub: TBitBtn;
    Image1: TImage;
    Memo1: TMemo;
    StatusBar1: TStatusBar;
    procedure BtnOpenGhubClick(Sender: TObject);
  private

  public

  end;

var
  FrmAbout: TFrmAbout;

implementation

{$R *.lfm}

procedure TFrmAbout.BtnOpenGhubClick(Sender: TObject);
begin
  if not OpenURL(GITHUB_URL) then
    ShowMessage('Não foi possível abrir a URL.');
end;

end.

