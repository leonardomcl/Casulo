unit compresscfg;

{$mode ObjFPC}{$H+}

interface

uses
  Classes, SysUtils, Forms, Controls, Graphics, Dialogs, StdCtrls, CasuloConfig;

type

  TFConfigCprsAlgo = class(TForm)
    CBStripStub: TCheckBox;
    RbCompressModeB: TRadioButton;
    RbCompressModeZ: TRadioButton;
    procedure FormClose(Sender: TObject; var CloseAction: TCloseAction);
  private

  public

  end;

var
  FConfigCprsAlgo: TFConfigCprsAlgo;

implementation

{$R *.lfm}

procedure TFConfigCprsAlgo.FormClose(Sender: TObject;
  var CloseAction: TCloseAction);
begin

  if(RbCompressModeB.Checked) then
     COMPACT_ALGORITHM := COMPACT_BROTLI
     else
     COMPACT_ALGORITHM := COMPACT_ZSTD;

  if(CBStripStub.Checked) then
     STRIP_STUB := True
     else
     STRIP_STUB := False
end;

end.

