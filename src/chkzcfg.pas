unit chkzcfg;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, ComCtrls, CasuloConfig;

type

  TFChkSizeCfg = class(TForm)
    StatusBar1: TStatusBar;
    ChkSize: TTrackBar;
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
  private

  public

  end;

var
  FChkSizeCfg: TFChkSizeCfg;

implementation

{$R *.lfm}

procedure TFChkSizeCfg.FormClose(Sender: TObject; var CloseAction: TCloseAction
  );
begin
   RCDATA_FRAGMENT_SIZE :=  ChkSize.Position * 1024;
end;

end.

