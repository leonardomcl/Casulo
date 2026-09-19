unit cfgtargetlinux;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, ComCtrls, StdCtrls, CasuloConfig;

type

  TFTargetLinux = class(TForm)
    RbMusl: TRadioButton;
    RBGnu: TRadioButton;
    StatusBar1: TStatusBar;
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
  private

  public

  end;

var
  FTargetLinux: TFTargetLinux;

implementation

{$R *.lfm}

procedure TFTargetLinux.FormClose(Sender: TObject; var CloseAction: TCloseAction
  );
begin
  if RbMusl.Checked then
  RUST_LINUX_TARGET := RUST_LINUX_TARGET_MUSL
  else
  RUST_LINUX_TARGET := RUST_LINUX_TARGET_GNU
end;

end.

