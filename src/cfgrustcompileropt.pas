unit cfgrustcompileropt;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, ComCtrls,
  ExtCtrls, CasuloConfig;

type

  TFRustCmpOpt = class(TForm)
    GroupBox1: TGroupBox;
    ListBox1: TListBox;
    lto: TLabel;
    RbLtoTrue: TRadioButton;
    RbLtoFalse: TRadioButton;
    StatusBar1: TStatusBar;
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
  private

  public

  end;

var
  FRustCmpOpt: TFRustCmpOpt;

implementation

{$R *.lfm}

procedure TFRustCmpOpt.FormClose(Sender: TObject; var CloseAction: TCloseAction);
begin
  LTO_CONFIG := RbLtoTrue.Checked;
  OPT_LEVEL_CONFIG := ListBox1.GetSelectedText;
end;

end.
