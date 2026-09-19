unit WindowsVersionInfo;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils;

type
  TWindowsVersionInfo = record
    CompanyName: string;
    FileDescription: string;
    ProductName: string;
    LegalCopyright: string;
    OriginalFilename: string;
    InternalName: string;
    ProductVersion: string;
    FileVersion: string;
  end;

function ExtractWindowsVersionInfo(
  const FileName: string;
  out Info: TWindowsVersionInfo
): Boolean;

{ Metadados de versão são gerados com o PRNG comum do FPC. }
function GenerateRandomVersionInfo: TWindowsVersionInfo;

implementation

const
  IMAGE_DOS_SIGNATURE = $5A4D;
  IMAGE_NT_SIGNATURE = $00004550;
  IMAGE_NT_OPTIONAL_HDR32 = $010B;
  IMAGE_NT_OPTIONAL_HDR64 = $020B;
  IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
  RT_VERSION = 16;

  RESOURCE_DIR_HEADER_SIZE = 16;
  RESOURCE_DIR_ENTRY_SIZE = 8;
  RESOURCE_DATA_ENTRY_SIZE = 16;
  SECTION_HEADER_SIZE = 40;

type
  TSectionInfo = record
    VirtualAddress: LongWord;
    VirtualSize: LongWord;
    RawAddress: LongWord;
    RawSize: LongWord;
  end;

  TSectionArray = array of TSectionInfo;

function Align4(Value: SizeUInt): SizeUInt; inline;
begin
  Result := (Value + 3) and not SizeUInt(3);
end;

function RangeValid(Offset, Count, Total: SizeUInt): Boolean; inline;
begin
  Result := (Offset <= Total) and (Count <= Total - Offset);
end;

function ReadU16(const Data: TBytes; Offset: SizeUInt; out Value: Word): Boolean;
begin
  Result := RangeValid(Offset, 2, Length(Data));
  if not Result then Exit;
  Value := Word(Data[Offset]) or (Word(Data[Offset + 1]) shl 8);
end;

function ReadU32(const Data: TBytes; Offset: SizeUInt; out Value: LongWord): Boolean;
begin
  Result := RangeValid(Offset, 4, Length(Data));
  if not Result then Exit;
  Value :=
    LongWord(Data[Offset]) or
    (LongWord(Data[Offset + 1]) shl 8) or
    (LongWord(Data[Offset + 2]) shl 16) or
    (LongWord(Data[Offset + 3]) shl 24);
end;

function LoadFileBytes(const FileName: string; out Data: TBytes): Boolean;
var
  Stream: TFileStream;
begin
  Result := False;
  SetLength(Data, 0);

  if not FileExists(FileName) then
    Exit;

  Stream := TFileStream.Create(FileName, fmOpenRead or fmShareDenyNone);
  try
    if Stream.Size <= 0 then
      Exit;

    if Stream.Size > High(Integer) then
      raise Exception.Create('Arquivo PE grande demais para esta rotina.');

    SetLength(Data, Integer(Stream.Size));
    Stream.Position := 0;
    Stream.ReadBuffer(Data[0], Length(Data));
    Result := True;
  finally
    Stream.Free;
  end;
end;

function RvaToFileOffset(
  RVA: LongWord;
  const Sections: TSectionArray;
  FileSize: SizeUInt;
  out Offset: SizeUInt
): Boolean;
var
  I: Integer;
  Span, Delta, Candidate: QWord;
  FirstSectionVA: QWord;
begin
  Result := False;
  Offset := 0;

  FirstSectionVA := High(QWord);
  for I := 0 to High(Sections) do
    if Sections[I].VirtualAddress < FirstSectionVA then
      FirstSectionVA := Sections[I].VirtualAddress;

  { RVAs antes da primeira seção pertencem aos headers. }
  if (QWord(RVA) < FirstSectionVA) and (QWord(RVA) < QWord(FileSize)) then
  begin
    Offset := RVA;
    Exit(True);
  end;

  for I := 0 to High(Sections) do
  begin
    Span := Sections[I].VirtualSize;
    if Sections[I].RawSize > Span then
      Span := Sections[I].RawSize;

    if Span = 0 then
      Continue;

    if (QWord(RVA) >= QWord(Sections[I].VirtualAddress)) and
       (QWord(RVA) < QWord(Sections[I].VirtualAddress) + Span) then
    begin
      Delta := QWord(RVA) - QWord(Sections[I].VirtualAddress);
      Candidate := QWord(Sections[I].RawAddress) + Delta;

      if Candidate >= QWord(FileSize) then
        Exit(False);

      Offset := SizeUInt(Candidate);
      Exit(True);
    end;
  end;
end;

function ReadUtf16Z(
  const Data: TBytes;
  StartOffset, LimitOffset: SizeUInt;
  out Value: string;
  out NextOffset: SizeUInt
): Boolean;
var
  P: SizeUInt;
  W: Word;
  U: UnicodeString;
  N: Integer;
begin
  Result := False;
  Value := '';
  NextOffset := StartOffset;

  if LimitOffset > SizeUInt(Length(Data)) then
    LimitOffset := Length(Data);

  P := StartOffset;
  N := 0;
  SetLength(U, 0);

  while P + 2 <= LimitOffset do
  begin
    if not ReadU16(Data, P, W) then
      Exit;

    Inc(P, 2);

    if W = 0 then
    begin
      NextOffset := P;
      Value := UTF8Encode(U);
      Exit(True);
    end;

    Inc(N);
    SetLength(U, N);
    U[N] := WideChar(W);
  end;
end;

function ReadUtf16Value(
  const Data: TBytes;
  Offset, CharCount, BlockEnd: SizeUInt
): string;
var
  I, N: SizeUInt;
  W: Word;
  U: UnicodeString;
begin
  Result := '';

  if CharCount = 0 then
    Exit;

  if BlockEnd > SizeUInt(Length(Data)) then
    BlockEnd := Length(Data);

  N := 0;
  SetLength(U, 0);

  for I := 0 to CharCount - 1 do
  begin
    if not RangeValid(Offset + I * 2, 2, BlockEnd) then
      Break;

    if not ReadU16(Data, Offset + I * 2, W) then
      Break;

    if W = 0 then
      Break;

    Inc(N);
    SetLength(U, N);
    U[N] := WideChar(W);
  end;

  Result := UTF8Encode(U);
end;

procedure AssignVersionString(
  const Key, Value: string;
  var Info: TWindowsVersionInfo
);
begin
  if Value = '' then
    Exit;

  if SameText(Key, 'CompanyName') then
  begin
    if Info.CompanyName = '' then Info.CompanyName := Value;
  end
  else if SameText(Key, 'FileDescription') then
  begin
    if Info.FileDescription = '' then Info.FileDescription := Value;
  end
  else if SameText(Key, 'ProductName') then
  begin
    if Info.ProductName = '' then Info.ProductName := Value;
  end
  else if SameText(Key, 'LegalCopyright') then
  begin
    if Info.LegalCopyright = '' then Info.LegalCopyright := Value;
  end
  else if SameText(Key, 'OriginalFilename') then
  begin
    if Info.OriginalFilename = '' then Info.OriginalFilename := Value;
  end
  else if SameText(Key, 'InternalName') then
  begin
    if Info.InternalName = '' then Info.InternalName := Value;
  end
  else if SameText(Key, 'ProductVersion') then
  begin
    if Info.ProductVersion = '' then Info.ProductVersion := Value;
  end
  else if SameText(Key, 'FileVersion') then
  begin
    if Info.FileVersion = '' then Info.FileVersion := Value;
  end;
end;

function FormatFixedVersion(MS, LS: LongWord): string;
begin
  Result := Format('%d.%d.%d.%d', [
    (MS shr 16) and $FFFF,
    MS and $FFFF,
    (LS shr 16) and $FFFF,
    LS and $FFFF
  ]);
end;

procedure ParseVersionBlock(
  const Data: TBytes;
  BlockOffset, ParentEnd: SizeUInt;
  var Info: TWindowsVersionInfo;
  Depth: Integer
);
var
  WLength, WValueLength, WType: Word;
  BlockEnd, AfterKey, ValueOffset, ValueBytes, ChildOffset: SizeUInt;
  ChildLength: Word;
  Key, StringValue: string;
  Signature, FileVersionMS, FileVersionLS: LongWord;
  ProductVersionMS, ProductVersionLS: LongWord;
begin
  if Depth > 16 then Exit;
  if not RangeValid(BlockOffset, 6, ParentEnd) then Exit;

  if not ReadU16(Data, BlockOffset, WLength) then Exit;
  if not ReadU16(Data, BlockOffset + 2, WValueLength) then Exit;
  if not ReadU16(Data, BlockOffset + 4, WType) then Exit;

  if WLength < 6 then Exit;
  if SizeUInt(WLength) > ParentEnd - BlockOffset then Exit;

  BlockEnd := BlockOffset + WLength;
  if BlockEnd > SizeUInt(Length(Data)) then Exit;

  if not ReadUtf16Z(Data, BlockOffset + 6, BlockEnd, Key, AfterKey) then Exit;

  ValueOffset := Align4(AfterKey);
  if ValueOffset > BlockEnd then Exit;

  if WType = 1 then
    ValueBytes := SizeUInt(WValueLength) * 2
  else
    ValueBytes := WValueLength;

  if ValueBytes > BlockEnd - ValueOffset then
    ValueBytes := BlockEnd - ValueOffset;

  if (WType = 1) and (WValueLength > 0) then
  begin
    StringValue := ReadUtf16Value(Data, ValueOffset, WValueLength, BlockEnd);
    AssignVersionString(Key, StringValue, Info);
  end;

  if SameText(Key, 'VS_VERSION_INFO') and
     (WType = 0) and
     (WValueLength >= 24) and
     RangeValid(ValueOffset, 24, BlockEnd) then
  begin
    if ReadU32(Data, ValueOffset, Signature) and
       (Signature = $FEEF04BD) and
       ReadU32(Data, ValueOffset + 8, FileVersionMS) and
       ReadU32(Data, ValueOffset + 12, FileVersionLS) and
       ReadU32(Data, ValueOffset + 16, ProductVersionMS) and
       ReadU32(Data, ValueOffset + 20, ProductVersionLS) then
    begin
      if Info.FileVersion = '' then
        Info.FileVersion := FormatFixedVersion(FileVersionMS, FileVersionLS);

      if Info.ProductVersion = '' then
        Info.ProductVersion := FormatFixedVersion(ProductVersionMS, ProductVersionLS);
    end;
  end;

  ChildOffset := Align4(ValueOffset + ValueBytes);

  while ChildOffset + 6 <= BlockEnd do
  begin
    if not ReadU16(Data, ChildOffset, ChildLength) then Break;
    if ChildLength < 6 then Break;
    if SizeUInt(ChildLength) > BlockEnd - ChildOffset then Break;

    ParseVersionBlock(Data, ChildOffset, BlockEnd, Info, Depth + 1);
    ChildOffset := Align4(ChildOffset + ChildLength);
  end;
end;

function FindFirstResourceDataEntry(
  const Data: TBytes;
  ResourceBase: SizeUInt;
  DirectoryRelativeOffset: LongWord;
  ResourceLimit: SizeUInt;
  out DataRVA, DataSize: LongWord;
  Depth: Integer
): Boolean;
var
  DirectoryOffset, EntriesOffset, EntryOffset: SizeUInt;
  DataEntryOffset: SizeUInt;
  NamedCount, IdCount: Word;
  EntryCount, I: SizeUInt;
  NameOrId, Child, ChildRelative: LongWord;
begin
  Result := False;
  DataRVA := 0;
  DataSize := 0;

  if Depth > 8 then Exit;

  DirectoryOffset := ResourceBase + SizeUInt(DirectoryRelativeOffset);

  if not RangeValid(DirectoryOffset, RESOURCE_DIR_HEADER_SIZE, ResourceLimit) then
    Exit;

  if not ReadU16(Data, DirectoryOffset + 12, NamedCount) then Exit;
  if not ReadU16(Data, DirectoryOffset + 14, IdCount) then Exit;

  EntryCount := SizeUInt(NamedCount) + SizeUInt(IdCount);
  EntriesOffset := DirectoryOffset + RESOURCE_DIR_HEADER_SIZE;

  if EntryCount > (ResourceLimit - EntriesOffset) div RESOURCE_DIR_ENTRY_SIZE then
    Exit;

  for I := 0 to EntryCount - 1 do
  begin
    EntryOffset := EntriesOffset + I * RESOURCE_DIR_ENTRY_SIZE;

    if not ReadU32(Data, EntryOffset, NameOrId) then Exit;
    if not ReadU32(Data, EntryOffset + 4, Child) then Exit;

    ChildRelative := Child and $7FFFFFFF;

    if (Child and $80000000) <> 0 then
    begin
      if FindFirstResourceDataEntry(
        Data,
        ResourceBase,
        ChildRelative,
        ResourceLimit,
        DataRVA,
        DataSize,
        Depth + 1
      ) then
        Exit(True);
    end
    else
    begin
      DataEntryOffset := ResourceBase + SizeUInt(ChildRelative);

      if not RangeValid(DataEntryOffset, RESOURCE_DATA_ENTRY_SIZE, ResourceLimit) then
        Continue;

      if not ReadU32(Data, DataEntryOffset, DataRVA) then Continue;
      if not ReadU32(Data, DataEntryOffset + 4, DataSize) then Continue;

      Exit(True);
    end;
  end;
end;

function FindVersionResource(
  const Data: TBytes;
  ResourceBase: SizeUInt;
  ResourceSize: LongWord;
  out DataRVA, DataSize: LongWord
): Boolean;
var
  ResourceLimit, EntriesOffset, EntryOffset: SizeUInt;
  NamedCount, IdCount: Word;
  EntryCount, I: SizeUInt;
  NameOrId, Child, ResourceId: LongWord;
begin
  Result := False;
  DataRVA := 0;
  DataSize := 0;

  if ResourceSize = 0 then Exit;

  if ResourceBase > SizeUInt(Length(Data)) then Exit;

  if SizeUInt(ResourceSize) > SizeUInt(Length(Data)) - ResourceBase then
    ResourceLimit := Length(Data)
  else
    ResourceLimit := ResourceBase + ResourceSize;

  if not RangeValid(ResourceBase, RESOURCE_DIR_HEADER_SIZE, ResourceLimit) then
    Exit;

  if not ReadU16(Data, ResourceBase + 12, NamedCount) then Exit;
  if not ReadU16(Data, ResourceBase + 14, IdCount) then Exit;

  EntryCount := SizeUInt(NamedCount) + SizeUInt(IdCount);
  EntriesOffset := ResourceBase + RESOURCE_DIR_HEADER_SIZE;

  if EntryCount > (ResourceLimit - EntriesOffset) div RESOURCE_DIR_ENTRY_SIZE then
    Exit;

  for I := 0 to EntryCount - 1 do
  begin
    EntryOffset := EntriesOffset + I * RESOURCE_DIR_ENTRY_SIZE;

    if not ReadU32(Data, EntryOffset, NameOrId) then Exit;
    if not ReadU32(Data, EntryOffset + 4, Child) then Exit;

    if (NameOrId and $80000000) <> 0 then
      Continue;

    ResourceId := NameOrId and $FFFF;

    if ResourceId <> RT_VERSION then
      Continue;

    if (Child and $80000000) = 0 then
      Exit(False);

    Exit(FindFirstResourceDataEntry(
      Data,
      ResourceBase,
      Child and $7FFFFFFF,
      ResourceLimit,
      DataRVA,
      DataSize,
      0
    ));
  end;
end;

function ExtractWindowsVersionInfo(
  const FileName: string;
  out Info: TWindowsVersionInfo
): Boolean;
var
  Data: TBytes;
  DosSignature, NumberOfSections, SizeOfOptionalHeader, OptionalMagic: Word;
  PEOffset, PESignature, ResourceRVA, ResourceSize: LongWord;
  DataDirectoryOffset, ResourceDirectoryOffset: SizeUInt;
  OptionalHeaderOffset, SectionHeadersOffset, SectionOffset: SizeUInt;
  ResourceFileOffset, VersionFileOffset, VersionEnd: SizeUInt;
  VersionDataRVA, VersionDataSize: LongWord;
  Sections: TSectionArray;
  I: Integer;
begin
  Result := False;
  Info := Default(TWindowsVersionInfo);

  if not LoadFileBytes(FileName, Data) then Exit;

  try
    if not ReadU16(Data, 0, DosSignature) then Exit;
    if DosSignature <> IMAGE_DOS_SIGNATURE then Exit;

    if not ReadU32(Data, $3C, PEOffset) then Exit;
    if not RangeValid(PEOffset, 24, Length(Data)) then Exit;

    if not ReadU32(Data, PEOffset, PESignature) then Exit;
    if PESignature <> IMAGE_NT_SIGNATURE then Exit;

    if not ReadU16(Data, PEOffset + 6, NumberOfSections) then Exit;
    if NumberOfSections = 0 then Exit;

    if not ReadU16(Data, PEOffset + 20, SizeOfOptionalHeader) then Exit;

    OptionalHeaderOffset := PEOffset + 24;

    if not RangeValid(OptionalHeaderOffset, SizeOfOptionalHeader, Length(Data)) then
      Exit;

    if not ReadU16(Data, OptionalHeaderOffset, OptionalMagic) then Exit;

    case OptionalMagic of
      IMAGE_NT_OPTIONAL_HDR32:
        DataDirectoryOffset := OptionalHeaderOffset + 96;
      IMAGE_NT_OPTIONAL_HDR64:
        DataDirectoryOffset := OptionalHeaderOffset + 112;
    else
      Exit;
    end;

    ResourceDirectoryOffset :=
      DataDirectoryOffset + IMAGE_DIRECTORY_ENTRY_RESOURCE * 8;

    if not RangeValid(
      ResourceDirectoryOffset,
      8,
      OptionalHeaderOffset + SizeOfOptionalHeader
    ) then
      Exit;

    if not ReadU32(Data, ResourceDirectoryOffset, ResourceRVA) then Exit;
    if not ReadU32(Data, ResourceDirectoryOffset + 4, ResourceSize) then Exit;

    if (ResourceRVA = 0) or (ResourceSize = 0) then Exit;

    SectionHeadersOffset := OptionalHeaderOffset + SizeOfOptionalHeader;

    if not RangeValid(
      SectionHeadersOffset,
      SizeUInt(NumberOfSections) * SECTION_HEADER_SIZE,
      Length(Data)
    ) then
      Exit;

    SetLength(Sections, NumberOfSections);

    for I := 0 to NumberOfSections - 1 do
    begin
      SectionOffset := SectionHeadersOffset + SizeUInt(I) * SECTION_HEADER_SIZE;

      if not ReadU32(Data, SectionOffset + 8, Sections[I].VirtualSize) then Exit;
      if not ReadU32(Data, SectionOffset + 12, Sections[I].VirtualAddress) then Exit;
      if not ReadU32(Data, SectionOffset + 16, Sections[I].RawSize) then Exit;
      if not ReadU32(Data, SectionOffset + 20, Sections[I].RawAddress) then Exit;
    end;

    if not RvaToFileOffset(
      ResourceRVA,
      Sections,
      Length(Data),
      ResourceFileOffset
    ) then
      Exit;

    if not FindVersionResource(
      Data,
      ResourceFileOffset,
      ResourceSize,
      VersionDataRVA,
      VersionDataSize
    ) then
      Exit;

    if (VersionDataRVA = 0) or (VersionDataSize = 0) then Exit;

    if not RvaToFileOffset(
      VersionDataRVA,
      Sections,
      Length(Data),
      VersionFileOffset
    ) then
      Exit;

    if not RangeValid(VersionFileOffset, VersionDataSize, Length(Data)) then
      Exit;

    VersionEnd := VersionFileOffset + VersionDataSize;

    ParseVersionBlock(
      Data,
      VersionFileOffset,
      VersionEnd,
      Info,
      0
    );

    Result := True;

  finally
    if Length(Data) > 0 then
      FillChar(Data[0], Length(Data), 0);

    SetLength(Data, 0);
  end;
end;


{ VERSIONINFO }

const
  RANDOM_WORDS: array[0..249] of string = (
    'pluma', 'stella', 'inter', 'ghost', 'cyber', 'eagle', 'nova', 'atlas', 'lunar', 'solar',
    'vertex', 'pulse', 'orbit', 'nexus', 'ember', 'cobalt', 'silver', 'golden', 'crimson', 'azure',
    'violet', 'indigo', 'scarlet', 'ivory', 'obsidian', 'crystal', 'prism', 'vector', 'matrix', 'quantum',
    'pixel', 'byte', 'logic', 'binary', 'cipher', 'kernel', 'node', 'core', 'stack', 'cloud',
    'storm', 'thunder', 'frost', 'flame', 'blaze', 'spark', 'shadow', 'phantom', 'raven', 'wolf',
    'falcon', 'hawk', 'lion', 'tiger', 'panther', 'cobra', 'viper', 'dragon', 'phoenix', 'titan',
    'omega', 'alpha', 'sigma', 'delta', 'gamma', 'echo', 'sonic', 'turbo', 'hyper', 'rapid',
    'swift', 'bright', 'dark', 'light', 'steel', 'iron', 'bronze', 'copper', 'neon', 'plasma',
    'static', 'dynamic', 'flux', 'wave', 'signal', 'beacon', 'radar', 'laser', 'photon', 'proton',
    'electron', 'neutron', 'quark', 'boson', 'comet', 'meteor', 'asteroid', 'galaxy', 'cosmos', 'nebula',
    'star', 'planet', 'terra', 'ocean', 'river', 'lake', 'mountain', 'valley', 'forest', 'meadow',
    'canyon', 'desert', 'tundra', 'glacier', 'island', 'coast', 'harbor', 'bridge', 'tower', 'castle',
    'fortress', 'citadel', 'temple', 'shrine', 'garden', 'field', 'grove', 'stone', 'rock', 'marble',
    'granite', 'quartz', 'jade', 'ruby', 'sapphire', 'emerald', 'opal', 'pearl', 'diamond', 'topaz',
    'amber', 'onyx', 'metal', 'alloy', 'carbon', 'silicon', 'chrome', 'nickel', 'zinc', 'mercury',
    'helium', 'argon', 'xenon', 'oxygen', 'hydrogen', 'nitrogen', 'aurora', 'zenith', 'nadir', 'horizon',
    'dawn', 'dusk', 'midnight', 'noon', 'winter', 'summer', 'autumn', 'spring', 'north', 'south',
    'east', 'west', 'central', 'prime', 'apex', 'summit', 'crest', 'ridge', 'peak', 'base',
    'root', 'branch', 'leaf', 'seed', 'bloom', 'petal', 'thorn', 'ivy', 'moss', 'fern',
    'pine', 'cedar', 'oak', 'maple', 'willow', 'birch', 'ash', 'elm', 'orchid', 'lotus',
    'iris', 'rose', 'tulip', 'lily', 'dahlia', 'magnolia', 'coral', 'shell', 'reef', 'tide',
    'current', 'breeze', 'gale', 'mist', 'rain', 'snow', 'hail', 'cloudscape', 'wildfire', 'firestorm',
    'emberline', 'skylark', 'nightfall', 'daybreak', 'moonrise', 'sunrise', 'sunset', 'starlight', 'moonlight', 'daylight',
    'starfall', 'moonbeam', 'sunbeam', 'bluebird', 'redwood', 'blackwood', 'whitewood', 'greenfield', 'bluefield', 'redfield',
    'stonewall', 'ironwood', 'goldleaf', 'silverleaf', 'copperleaf', 'glasswing', 'firefly', 'dragonfly', 'butterfly', 'hummingbird'
  );

function CapitalizeWord(const S: string): string;
begin
  Result := S;

  if Result <> '' then
    Result[1] := UpCase(Result[1]);
end;

function GetRandomWord: string;
begin
  Result := RANDOM_WORDS[Random(Length(RANDOM_WORDS))];
end;

function GenerateCompoundName: string;
var
  WordA: string;
  WordB: string;
begin
  WordA := GetRandomWord;

  repeat
    WordB := GetRandomWord;
  until not SameText(WordA, WordB);

  Result :=
    CapitalizeWord(WordA) +
    CapitalizeWord(WordB);
end;

function GenerateVersionNumber: string;
begin
  Result := Format(
    '%d.%d.%d.%d',
    [
      1 + Random(9),     
      Random(20),        
      Random(1000),      
      Random(10000)      
    ]
  );
end;

function GenerateRandomVersionInfo: TWindowsVersionInfo;
var
  ProductBase: string;
  CompanyBase: string;
  Version: string;
  Year, Month, Day: Word;
begin
  Result := Default(TWindowsVersionInfo);

  ProductBase := GenerateCompoundName;
  CompanyBase := GenerateCompoundName;
  Version := GenerateVersionNumber;

  DecodeDate(Date, Year, Month, Day);

  Result.CompanyName :=
    CompanyBase + ' Software';

  Result.FileDescription :=
    ProductBase + ' Application';

  Result.ProductName :=
    ProductBase;

  Result.LegalCopyright :=
    Format(
      'Copyright © %d %s',
      [Year, CompanyBase]
    );

  Result.OriginalFilename :=
    ProductBase + '.exe';

  Result.InternalName :=
    ProductBase;

  Result.ProductVersion :=
    Version;

  Result.FileVersion :=
    Version;
end;


initialization
  Randomize;

end.
