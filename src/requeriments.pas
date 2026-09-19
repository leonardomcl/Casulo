unit Requeriments;

{$mode objfpc}{$H+}

interface

uses
  Classes,
  SysUtils
  {$IFDEF UNIX}
  , BaseUnix
  {$ENDIF}
  ;

type
  { Resultado por ferramenta, indexado pelo nome do executável. }
  TRequirementsResult = class
  private
    FItems: TStringList;

    function GetItem(const Name: string): Boolean;
    procedure SetItem(const Name: string; const Value: Boolean);

    function GetCount: Integer;
    function GetName(const Index: Integer): string;
    function GetStatus(const Index: Integer): Boolean;
  public
    constructor Create;
    destructor Destroy; override;

    property Items[const Name: string]: Boolean
      read GetItem
      write SetItem; default;

    property Count: Integer
      read GetCount;

    property Names[const Index: Integer]: string
      read GetName;

    property Status[const Index: Integer]: Boolean
      read GetStatus;
  end;

{ O chamador é responsável por liberar o TStringList retornado. }
function GetRequeriments: TRequirementsResult;


function ExecutableExists(const ExecutableName: string): Boolean;

implementation

constructor TRequirementsResult.Create;
begin
  inherited Create;

  FItems := TStringList.Create;
  FItems.NameValueSeparator := '=';
  FItems.CaseSensitive := False;
end;

destructor TRequirementsResult.Destroy;
begin
  FItems.Free;
  inherited Destroy;
end;

function TRequirementsResult.GetItem(const Name: string): Boolean;
var
  Index: Integer;
begin
  Index := FItems.IndexOfName(Name);

  if Index < 0 then
    Exit(False);

  Result := SameText(FItems.ValueFromIndex[Index], 'true');
end;

procedure TRequirementsResult.SetItem(
  const Name: string;
  const Value: Boolean
);
begin
  if Value then
    FItems.Values[Name] := 'true'
  else
    FItems.Values[Name] := 'false';
end;

function TRequirementsResult.GetCount: Integer;
begin
  Result := FItems.Count;
end;

function TRequirementsResult.GetName(
  const Index: Integer
): string;
begin
  if (Index < 0) or (Index >= FItems.Count) then
    Exit('');

  Result := FItems.Names[Index];
end;

function TRequirementsResult.GetStatus(
  const Index: Integer
): Boolean;
begin
  if (Index < 0) or (Index >= FItems.Count) then
    Exit(False);

  Result := SameText(
    FItems.ValueFromIndex[Index],
    'true'
  );
end;

function IsExecutableFile(const FileName: string): Boolean;
begin
  Result := FileExists(FileName);

  {$IFDEF UNIX}
  if Result then
    Result := fpAccess(PChar(FileName), X_OK) = 0;
  {$ENDIF}
end;

function ExecutableExists(const ExecutableName: string): Boolean;
var
  FoundPath: string;
  SearchPath: string;
  HomePath: string;
  CargoBinPath: string;
begin
  Result := False;

  if Trim(ExecutableName) = '' then
    Exit;

  
  if Pos(DirectorySeparator, ExecutableName) > 0 then
  begin
    Result := IsExecutableFile(ExecutableName);
    Exit;
  end;

  
  SearchPath := GetEnvironmentVariable('PATH');

  if SearchPath <> '' then
  begin
    FoundPath := FileSearch(ExecutableName, SearchPath);

    if (FoundPath <> '') and IsExecutableFile(FoundPath) then
      Exit(True);
  end;

  { Sessões gráficas nem sempre incluem ~/.cargo/bin no PATH. }
  HomePath := GetEnvironmentVariable('HOME');

  if HomePath <> '' then
  begin
    CargoBinPath :=
      IncludeTrailingPathDelimiter(HomePath) +
      '.cargo' +
      DirectorySeparator +
      'bin' +
      DirectorySeparator +
      ExecutableName;

    if IsExecutableFile(CargoBinPath) then
      Exit(True);
  end;
end;

function GetRequeriments: TRequirementsResult;
begin
  Result := TRequirementsResult.Create;

  
  Result['cargo']      := ExecutableExists('cargo');
  Result['rustc']      := ExecutableExists('rustc');
  Result['rustup']     := ExecutableExists('rustup');
  Result['cargo-xwin'] := ExecutableExists('cargo-xwin');

  
  Result['zstd']       := ExecutableExists('zstd');
  Result['brotli']     := ExecutableExists('brotli');

  
  Result['strip']      := ExecutableExists('strip');
  Result['magick'] := ExecutableExists('magick');
end;

end.
