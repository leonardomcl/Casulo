program Casulo;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  {$IFDEF HASAMIGA}
  athreads,
  {$ENDIF}
  Interfaces, // this includes the LCL widgetset
  Forms, Principal, Requeriments, reswindows, compresscfg, cfgimgbasewin,
chkzcfg, cfgrustcompileropt, cfgtargetlinux, about
  { you can add units after this };

{$R *.res}

begin
  RequireDerivedFormResource:=True;
  Application.Title:='Casulo v1.0';
  Application.Scaled:=True;
  {$PUSH}{$WARN 5044 OFF}
  Application.MainFormOnTaskbar:=True;
  {$POP}
  Application.Initialize;
  Application.CreateForm(TFPrincipal, FPrincipal);
  Application.CreateForm(TFResWindows, FResWindows);
  Application.CreateForm(TFConfigCprsAlgo, FConfigCprsAlgo);
  Application.CreateForm(TFImageBaseWin, FImageBaseWin);
  Application.CreateForm(TFChkSizeCfg, FChkSizeCfg);
  Application.CreateForm(TFRustCmpOpt, FRustCmpOpt);
  Application.CreateForm(TFTargetLinux, FTargetLinux);
  Application.CreateForm(TFrmAbout, FrmAbout);
  Application.Run;
end.

