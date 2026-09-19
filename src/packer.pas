unit Packer;

{$mode objfpc}{$H+}

interface

uses
  SysUtils, Classes, BaseUnix,
  DCPrijndael, DCPsha256,
  zstream;

type
  TDebugProc = procedure(const Msg: string) of object;
  TQWordArray = array of QWord;

const
  CONTAINER_VERSION = 4;
  BUILD_ID_SIZE     = 16;
  SECRET_SIZE       = 32;
  SALT_SIZE         = 32;
  CBC_IV_SIZE       = 16;
  KEY_SIZE          = 32;
  HMAC_TAG_SIZE     = 32;
  HMAC_BLOCK_SIZE   = 64;

  // Header v1: version/flags/reserved + BuildID + salt + IV + cipher_len.
  CONTAINER_HEADER_SIZE = 1 + 1 + 2 + BUILD_ID_SIZE + SALT_SIZE + CBC_IV_SIZE + 8 + 8;

  MAX_CONTAINER_SIZE = Int64(512) * 1024 * 1024;
  MAX_PAYLOAD_SIZE   = Int64(512) * 1024 * 1024;

  // Região fragmentada: chunks, diretório, footer e trailer.
  // Chunk = header(88) + ciphertext + tag(32).
  // Diretório = N entradas de (offset:u64, tamanho:u64).
  FRAG_FORMAT_VERSION = 4;
  FRAG_CHUNK_VERSION  = 1;
  // FooterMagic e labels de derivação são gerados por build.
  FRAG_LABEL_SIZE     = 16;                        
  TARGET_CHUNK_SIZE   = 128 * 1024;                
  MAX_CHUNKS          = 1024;                     

  CHUNK_HEADER_SIZE   = 1 + 1 + 2 + 4 + BUILD_ID_SIZE + SALT_SIZE + CBC_IV_SIZE + 8 + 8; 
  FRAG_DIR_ENTRY_SIZE = 8 + 8;                    
  FRAG_FOOTER_SIZE    = 8 + 4 + 4 + 8 + 8 + 8;    
  FRAG_TRAILER_SIZE   = HMAC_TAG_SIZE;            

function LerArquivo(const Caminho: string): TBytes;
function RandomBytes(Size: Integer): TBytes;
function HMAC_SHA256(const Key, Data: TBytes): TBytes;
function HKDF_SHA256(const IKM, Salt, Info: TBytes; KeyLen: Integer): TBytes;
function DeriveContainerKeys(const Secret, Salt, BuildID: TBytes;
  out EncKey, MacKey: TBytes): Boolean;
function CompressData(const Data: TBytes): TBytes;
function DecompressData(const Data: TBytes; MaxOutputSize: Int64): TBytes;
function EncryptContainer(const Payload, Secret: TBytes;
  out BuildID, Container: TBytes): Boolean;

// Fragmenta e cifra o stream já comprimido; o tamanho original fica no footer.
function EncryptFragmented(const CompressedPayload: TBytes; OriginalSize: Int64;
  const Secret: TBytes; out Magics: TQWordArray; out FooterMagic: QWord;
  out FragLabel, MetaLabel: TBytes; out PackedRegion: TBytes): Boolean;

procedure SetDebugCallback(Callback: TDebugProc);

implementation

var
  DebugCallback: TDebugProc;

procedure InternalDebugLog(const Msg: string);
begin
  if Assigned(DebugCallback) then
    DebugCallback(Msg)
  else
    Writeln(Msg);
end;

procedure SetDebugCallback(Callback: TDebugProc);
begin
  DebugCallback := Callback;
end;

function BytesConcat(const A, B: TBytes): TBytes;
var
  LA, LB: Integer;
begin
  LA := Length(A);
  LB := Length(B);
  SetLength(Result, LA + LB);
  if LA > 0 then
    Move(A[0], Result[0], LA);
  if LB > 0 then
    Move(B[0], Result[LA], LB);
end;

function OneByte(Value: Byte): TBytes;
begin
  SetLength(Result, 1);
  Result[0] := Value;
end;

function BytesConcat3(const A, B, C: TBytes): TBytes;
begin
  Result := BytesConcat(BytesConcat(A, B), C);
end;

function HashSHA256(const Data: TBytes): TBytes;
var
  Hash: TDCP_sha256;
begin
  SetLength(Result, 32);
  Hash := TDCP_sha256.Create(nil);
  try
    Hash.Init;
    if Length(Data) > 0 then
      Hash.Update(Data[0], Length(Data));
    Hash.Final(Result[0]);
  finally
    Hash.Free;
  end;
end;

function HMAC_SHA256(const Key, Data: TBytes): TBytes;
var
  K0, Ipad, Opad, Inner: TBytes;
  KeyHash: TBytes;
  I: Integer;
  Hash: TDCP_sha256;
begin
  SetLength(K0, HMAC_BLOCK_SIZE);
  FillChar(K0[0], Length(K0), 0);

  if Length(Key) > HMAC_BLOCK_SIZE then
  begin
    KeyHash := HashSHA256(Key);
    Move(KeyHash[0], K0[0], Length(KeyHash));
  end
  else if Length(Key) > 0 then
    Move(Key[0], K0[0], Length(Key));

  SetLength(Ipad, HMAC_BLOCK_SIZE);
  SetLength(Opad, HMAC_BLOCK_SIZE);
  for I := 0 to HMAC_BLOCK_SIZE - 1 do
  begin
    Ipad[I] := K0[I] xor $36;
    Opad[I] := K0[I] xor $5C;
  end;

  Hash := TDCP_sha256.Create(nil);
  try
    Hash.Init;
    Hash.Update(Ipad[0], Length(Ipad));
    if Length(Data) > 0 then
      Hash.Update(Data[0], Length(Data));
    SetLength(Inner, 32);
    Hash.Final(Inner[0]);

    Hash.Init;
    Hash.Update(Opad[0], Length(Opad));
    Hash.Update(Inner[0], Length(Inner));
    SetLength(Result, 32);
    Hash.Final(Result[0]);
  finally
    Hash.Free;
  end;

  
  SetLength(K0, 0);
  SetLength(Ipad, 0);
  SetLength(Opad, 0);
  SetLength(Inner, 0);
end;

function HKDF_SHA256(const IKM, Salt, Info: TBytes; KeyLen: Integer): TBytes;
var
  PRK, T, BlockInput, Block: TBytes;
  Counter, CopyLen, Need: Integer;
begin
  if (KeyLen <= 0) or (KeyLen > 255 * 32) then
    raise Exception.Create('HKDF: tamanho de chave inválido.');

  if Length(Salt) = 0 then
  begin
    SetLength(PRK, 32);
    FillChar(PRK[0], Length(PRK), 0);
  end
  else
    PRK := HMAC_SHA256(Salt, IKM);

  SetLength(Result, KeyLen);
  SetLength(T, 0);
  Counter := 1;
  Need := KeyLen;

  while Need > 0 do
  begin
    BlockInput := BytesConcat3(T, Info, OneByte(Byte(Counter)));
    Block := HMAC_SHA256(PRK, BlockInput);

    if Need < Length(Block) then
      CopyLen := Need
    else
      CopyLen := Length(Block);

    Move(Block[0], Result[KeyLen - Need], CopyLen);
    Dec(Need, CopyLen);

    T := Block;
    Inc(Counter);
  end;
end;

function MakeInfo(const BuildID: TBytes): TBytes;
const
  Prefix: AnsiString = 'v4';
var
  P: TBytes;
begin
  SetLength(P, Length(Prefix));
  if Length(Prefix) > 0 then
    Move(Prefix[1], P[0], Length(Prefix));
  Result := BytesConcat(P, BuildID);
end;

function DeriveContainerKeys(const Secret, Salt, BuildID: TBytes;
  out EncKey, MacKey: TBytes): Boolean;
var
  OKM, Info: TBytes;
begin
  Result := False;
  if Length(Secret) <> SECRET_SIZE then Exit;
  if Length(Salt) <> SALT_SIZE then Exit;
  if Length(BuildID) <> BUILD_ID_SIZE then Exit;

  Info := MakeInfo(BuildID);
  OKM := HKDF_SHA256(Secret, Salt, Info, KEY_SIZE * 2);
  if Length(OKM) <> KEY_SIZE * 2 then Exit;

  SetLength(EncKey, KEY_SIZE);
  SetLength(MacKey, KEY_SIZE);
  Move(OKM[0], EncKey[0], KEY_SIZE);
  Move(OKM[KEY_SIZE], MacKey[0], KEY_SIZE);
  Result := True;
end;

function RandomBytes(Size: Integer): TBytes;
var
  FS: TFileStream;
  ReadNow, Total: Integer;
begin
  if Size < 0 then
    raise Exception.Create('RandomBytes: tamanho inválido.');
  SetLength(Result, Size);
  if Size = 0 then Exit;

  
  FS := TFileStream.Create('/dev/urandom', fmOpenRead or fmShareDenyNone);
  try
    Total := 0;
    while Total < Size do
    begin
      ReadNow := FS.Read(Result[Total], Size - Total);
      if ReadNow <= 0 then
        raise Exception.Create('Falha ao obter bytes aleatórios de /dev/urandom.');
      Inc(Total, ReadNow);
    end;
  finally
    FS.Free;
  end;
end;

function LerArquivo(const Caminho: string): TBytes;
var
  FS: TFileStream;
  Size: Int64;
begin
  InternalDebugLog('LerArquivo: ' + Caminho);
  FS := TFileStream.Create(Caminho, fmOpenRead or fmShareDenyWrite);
  try
    Size := FS.Size;
    if Size > MAX_PAYLOAD_SIZE then
      raise Exception.CreateFmt('Arquivo excede o limite de %d bytes.', [MAX_PAYLOAD_SIZE]);
    if Size < 0 then
      raise Exception.Create('Tamanho de arquivo inválido.');

    SetLength(Result, Integer(Size));
    if Size > 0 then
      FS.ReadBuffer(Result[0], Integer(Size));
  finally
    FS.Free;
  end;
end;

function CompressData(const Data: TBytes): TBytes;
var
  Input, Output: TMemoryStream;
  Compressor: TCompressionStream;
  Size: Integer;
begin
  if Length(Data) = 0 then
    raise Exception.Create('CompressData: dados vazios.');

  Input := TMemoryStream.Create;
  Output := TMemoryStream.Create;
  try
    Input.WriteBuffer(Data[0], Length(Data));
    Input.Position := 0;

    Compressor := TCompressionStream.Create(clMax, Output);
    try
      Compressor.CopyFrom(Input, Input.Size);
    finally
      Compressor.Free;
    end;

    Size := Integer(Output.Size);
    SetLength(Result, Size);
    if Size > 0 then
    begin
      Output.Position := 0;
      Output.ReadBuffer(Result[0], Size);
    end;
  finally
    Input.Free;
    Output.Free;
  end;
end;

function DecompressData(const Data: TBytes; MaxOutputSize: Int64): TBytes;
var
  Input, Output: TMemoryStream;
  Decompressor: TDecompressionStream;
  Buffer: array[0..16383] of Byte;
  BytesRead: Integer;
  NewSize: Int64;
begin
  if Length(Data) = 0 then
    raise Exception.Create('DecompressData: dados vazios.');
  if MaxOutputSize <= 0 then
    raise Exception.Create('DecompressData: limite inválido.');

  Input := TMemoryStream.Create;
  Output := TMemoryStream.Create;
  try
    Input.WriteBuffer(Data[0], Length(Data));
    Input.Position := 0;

    Decompressor := TDecompressionStream.Create(Input);
    try
      repeat
        BytesRead := Decompressor.Read(Buffer, SizeOf(Buffer));
        if BytesRead > 0 then
        begin
          NewSize := Output.Size + BytesRead;
          if NewSize > MaxOutputSize then
            raise Exception.Create('Payload descomprimido excede o limite configurado.');
          Output.WriteBuffer(Buffer[0], BytesRead);
        end;
      until BytesRead = 0;
    finally
      Decompressor.Free;
    end;

    if Output.Size = 0 then
      raise Exception.Create('Payload descomprimido vazio.');

    SetLength(Result, Integer(Output.Size));
    Output.Position := 0;
    Output.ReadBuffer(Result[0], Integer(Output.Size));
  finally
    Input.Free;
    Output.Free;
  end;
end;

procedure PutQWordLE(var Dest: TBytes; Offset: Integer; Value: QWord);
var
  I: Integer;
begin
  for I := 0 to 7 do
    Dest[Offset + I] := Byte(Value shr (8 * I));
end;

procedure PutDWordLE(var Dest: TBytes; Offset: Integer; Value: LongWord);
var
  I: Integer;
begin
  for I := 0 to 3 do
    Dest[Offset + I] := Byte(Value shr (8 * I));
end;

function GetRandomQWord: QWord;
var
  B: TBytes;
begin
  B := RandomBytes(8);
  Result := 0;
  Result := QWord(B[0]) or (QWord(B[1]) shl 8) or (QWord(B[2]) shl 16) or
            (QWord(B[3]) shl 24) or (QWord(B[4]) shl 32) or (QWord(B[5]) shl 40) or
            (QWord(B[6]) shl 48) or (QWord(B[7]) shl 56);
end;

// Subchave usada no MAC do diretório e do footer.
function DeriveMetaKey(const Secret, MetaLabel: TBytes): TBytes;
begin
  Result := HMAC_SHA256(Secret, MetaLabel);
end;

// HKDF info: FragLabel || BuildID || Magic || Index.
function MakeChunkInfo(const FragLabel, BuildID: TBytes; Magic: QWord;
  Index: LongWord): TBytes;
var
  M, Idx: TBytes;
begin
  SetLength(M, 8);
  PutQWordLE(M, 0, Magic);
  SetLength(Idx, 4);
  PutDWordLE(Idx, 0, Index);
  Result := BytesConcat(BytesConcat(BytesConcat(FragLabel, BuildID), M), Idx);
end;

function GetQWordLE(const Src: TBytes; Offset: Integer): QWord;
var
  I: Integer;
begin
  Result := 0;
  for I := 0 to 7 do
    Result := Result or (QWord(Src[Offset + I]) shl (8 * I));
end;

function PKCS7Pad(const PlainText: TBytes): TBytes;
var
  PadLen, DataLen, I: Integer;
begin
  DataLen := Length(PlainText);
  PadLen := CBC_IV_SIZE - (DataLen mod CBC_IV_SIZE);
  SetLength(Result, DataLen + PadLen);
  if DataLen > 0 then
    Move(PlainText[0], Result[0], DataLen);
  for I := DataLen to Length(Result) - 1 do
    Result[I] := Byte(PadLen);
end;

function AES_CBC_Encrypt(const PlainText, Key, IV: TBytes): TBytes;
var
  Cipher: TDCP_rijndael;
  Padded: TBytes;
begin
  if Length(Key) <> KEY_SIZE then
    raise Exception.Create('AES: chave inválida.');
  if Length(IV) <> CBC_IV_SIZE then
    raise Exception.Create('AES: IV inválido.');

  Padded := PKCS7Pad(PlainText);
  SetLength(Result, Length(Padded));

  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(Key[0], KEY_SIZE * 8, @IV[0]);
    Cipher.EncryptCBC(Padded[0], Result[0], Length(Padded));
  finally
    Cipher.Free;
  end;
end;

function ConstantTimeEqual(const A, B: TBytes): Boolean;
var
  I: Integer;
  Diff: Byte;
begin
  if Length(A) <> Length(B) then
    Exit(False);
  Diff := 0;
  for I := 0 to Length(A) - 1 do
    Diff := Diff or (A[I] xor B[I]);
  Result := Diff = 0;
end;

function EncryptContainer(const Payload, Secret: TBytes;
  out BuildID, Container: TBytes): Boolean;
var
  Compressed, Salt, IV: TBytes;
  EncKey, MacKey, CipherText, Header, AuthInput, Tag: TBytes;
  InfoLen: Integer;
  CipherLenOffset, PlainLenOffset: Integer;
begin
  Result := False;
  SetLength(BuildID, 0);
  SetLength(Container, 0);

  if Length(Payload) = 0 then
    raise Exception.Create('Payload vazio.');
  if Length(Payload) > MAX_PAYLOAD_SIZE then
    raise Exception.Create('Payload excede o limite configurado.');
  if Length(Secret) <> SECRET_SIZE then
    raise Exception.Create('SEGREDO deve ter 32 bytes.');

  InternalDebugLog('Comprimindo payload...');
  Compressed := CompressData(Payload);
  InternalDebugLog(Format('Payload comprimido: %d bytes', [Length(Compressed)]));

  BuildID := RandomBytes(BUILD_ID_SIZE);
  Salt := RandomBytes(SALT_SIZE);
  IV := RandomBytes(CBC_IV_SIZE);

  if not DeriveContainerKeys(Secret, Salt, BuildID, EncKey, MacKey) then
    raise Exception.Create('Falha ao derivar chaves.');

  InternalDebugLog('Derivando chaves com HKDF-SHA256...');
  CipherText := AES_CBC_Encrypt(Compressed, EncKey, IV);

  SetLength(Header, CONTAINER_HEADER_SIZE);
  FillChar(Header[0], Length(Header), 0);
  Header[0] := CONTAINER_VERSION;
  Header[1] := 0; 
  Header[2] := 0;
  Header[3] := 0;

  Move(BuildID[0], Header[4], BUILD_ID_SIZE);
  Move(Salt[0], Header[4 + BUILD_ID_SIZE], SALT_SIZE);
  Move(IV[0], Header[4 + BUILD_ID_SIZE + SALT_SIZE], CBC_IV_SIZE);

  CipherLenOffset := 4 + BUILD_ID_SIZE + SALT_SIZE + CBC_IV_SIZE;
  PlainLenOffset := CipherLenOffset + 8;
  PutQWordLE(Header, CipherLenOffset, QWord(Length(CipherText)));
  PutQWordLE(Header, PlainLenOffset, QWord(Length(Payload)));

  AuthInput := BytesConcat(Header, CipherText);
  Tag := HMAC_SHA256(MacKey, AuthInput);

  SetLength(Container, Length(Header) + Length(CipherText) + HMAC_TAG_SIZE);
  Move(Header[0], Container[0], Length(Header));
  Move(CipherText[0], Container[Length(Header)], Length(CipherText));
  Move(Tag[0], Container[Length(Header) + Length(CipherText)], HMAC_TAG_SIZE);

  if Length(Container) > MAX_CONTAINER_SIZE then
    raise Exception.Create('Container excede o limite configurado.');

  InternalDebugLog(Format('Container criado: %d bytes', [Length(Container)]));
  Result := True;
end;


function EncryptFragmented(const CompressedPayload: TBytes; OriginalSize: Int64;
  const Secret: TBytes; out Magics: TQWordArray; out FooterMagic: QWord;
  out FragLabel, MetaLabel: TBytes; out PackedRegion: TBytes): Boolean;
var
  N, I, CompLen, Base, Rem, Off, ThisLen: Integer;
  ChunkPlain, Salt, IV, BuildID, Info: TBytes;
  EncKey, MacKey, OKM, CipherText, Header, AuthInput, Tag: TBytes;
  State: TBytes;
  Chunks: array of TBytes;
  Dir, Footer, MetaKey, Trailer: TBytes;
  TotalChunks: Int64;
  CipherLenOff, PlainLenOff: Integer;
  PadLen: Integer;
begin
  Result := False;
  SetLength(PackedRegion, 0);
  SetLength(Magics, 0);
  FooterMagic := 0;

  if OriginalSize <= 0 then
    raise Exception.Create('Tamanho original inválido.');
  if OriginalSize > MAX_PAYLOAD_SIZE then
    raise Exception.Create('Payload excede o limite configurado.');
  if Length(CompressedPayload) = 0 then
    raise Exception.Create('Stream comprimido vazio.');
  if Length(Secret) <> SECRET_SIZE then
    raise Exception.Create('SEGREDO deve ter 32 bytes.');

  // Labels de derivação deste build.
  FragLabel := RandomBytes(FRAG_LABEL_SIZE);
  MetaLabel := RandomBytes(FRAG_LABEL_SIZE);


  CompLen := Length(CompressedPayload);
  InternalDebugLog(Format('Stream comprimido recebido: %d bytes (original: %d)',
    [CompLen, OriginalSize]));

  
  N := (CompLen + TARGET_CHUNK_SIZE - 1) div TARGET_CHUNK_SIZE;
  if N < 1 then N := 1;
  if N > MAX_CHUNKS then N := MAX_CHUNKS;
  if N > CompLen then N := CompLen;   
  if N < 1 then N := 1;
  InternalDebugLog(Format('Fragmentando em %d container(es)...', [N]));

  SetLength(Magics, N);
  SetLength(Chunks, N);

  Base := CompLen div N;
  Rem  := CompLen mod N;

  
  SetLength(State, SECRET_SIZE);
  Move(Secret[0], State[0], SECRET_SIZE);

  Off := 0;
  for I := 0 to N - 1 do
  begin
    if I < Rem then ThisLen := Base + 1 else ThisLen := Base;

    SetLength(ChunkPlain, ThisLen);
    if ThisLen > 0 then
      Move(CompressedPayload[Off], ChunkPlain[0], ThisLen);
    Inc(Off, ThisLen);

    Magics[I] := GetRandomQWord;

    BuildID := RandomBytes(BUILD_ID_SIZE);
    Salt    := RandomBytes(SALT_SIZE);
    IV      := RandomBytes(CBC_IV_SIZE);

    
    Info := MakeChunkInfo(FragLabel, BuildID, Magics[I], LongWord(I));
    OKM := HKDF_SHA256(State, Salt, Info, KEY_SIZE * 2);
    if Length(OKM) <> KEY_SIZE * 2 then
      raise Exception.Create('Falha ao derivar chaves do chunk.');
    SetLength(EncKey, KEY_SIZE);
    SetLength(MacKey, KEY_SIZE);
    Move(OKM[0], EncKey[0], KEY_SIZE);
    Move(OKM[KEY_SIZE], MacKey[0], KEY_SIZE);

    CipherText := AES_CBC_Encrypt(ChunkPlain, EncKey, IV);

    SetLength(Header, CHUNK_HEADER_SIZE);
    FillChar(Header[0], Length(Header), 0);
    Header[0] := FRAG_CHUNK_VERSION;
    Header[1] := 0; 
    Header[2] := 0;
    Header[3] := 0;
    PutDWordLE(Header, 4, LongWord(I));
    Move(BuildID[0], Header[8], BUILD_ID_SIZE);
    Move(Salt[0], Header[8 + BUILD_ID_SIZE], SALT_SIZE);
    Move(IV[0], Header[8 + BUILD_ID_SIZE + SALT_SIZE], CBC_IV_SIZE);
    CipherLenOff := 8 + BUILD_ID_SIZE + SALT_SIZE + CBC_IV_SIZE;
    PlainLenOff  := CipherLenOff + 8;
    PutQWordLE(Header, CipherLenOff, QWord(Length(CipherText)));
    PutQWordLE(Header, PlainLenOff, QWord(ThisLen));

    AuthInput := BytesConcat(Header, CipherText);
    Tag := HMAC_SHA256(MacKey, AuthInput);

    Chunks[I] := BytesConcat(AuthInput, Tag);

    
    State := HMAC_SHA256(State, ChunkPlain);

    
    if Length(EncKey) > 0 then FillChar(EncKey[0], Length(EncKey), 0);
    if Length(MacKey) > 0 then FillChar(MacKey[0], Length(MacKey), 0);
    if Length(ChunkPlain) > 0 then FillChar(ChunkPlain[0], Length(ChunkPlain), 0);
  end;

  
  SetLength(Dir, N * FRAG_DIR_ENTRY_SIZE);
  TotalChunks := 0;
  for I := 0 to N - 1 do
    TotalChunks := TotalChunks + Length(Chunks[I]);

  SetLength(PackedRegion, Integer(TotalChunks));
  Off := 0;
  for I := 0 to N - 1 do
  begin
    if Length(Chunks[I]) > 0 then
      Move(Chunks[I][0], PackedRegion[Off], Length(Chunks[I]));
    PutQWordLE(Dir, I * FRAG_DIR_ENTRY_SIZE, QWord(Off));
    PutQWordLE(Dir, I * FRAG_DIR_ENTRY_SIZE + 8, QWord(Length(Chunks[I])));
    Inc(Off, Length(Chunks[I]));
  end;

  
  FooterMagic := GetRandomQWord;
  SetLength(Footer, FRAG_FOOTER_SIZE);
  FillChar(Footer[0], Length(Footer), 0);
  PutQWordLE(Footer, 0, FooterMagic);
  PutDWordLE(Footer, 8, LongWord(FRAG_FORMAT_VERSION));
  PutDWordLE(Footer, 12, LongWord(N));
  PutQWordLE(Footer, 16, QWord(Length(Dir)));
  PutQWordLE(Footer, 24,
    QWord(TotalChunks + Length(Dir) + FRAG_FOOTER_SIZE + FRAG_TRAILER_SIZE));
  PutQWordLE(Footer, 32, QWord(OriginalSize));

  // O trailer autentica o diretório e o footer antes da leitura dos chunks.
  MetaKey := DeriveMetaKey(Secret, MetaLabel);
  Trailer := HMAC_SHA256(MetaKey, BytesConcat(Dir, Footer));

  PackedRegion :=
    BytesConcat(BytesConcat(BytesConcat(PackedRegion, Dir), Footer), Trailer);

  // Mantém a região alinhada para evitar padding extra no RCDATA.
  // packed_size continua representando o tamanho lógico, sem esse padding.
  PadLen := (8 - (Length(PackedRegion) mod 8)) mod 8;
  if PadLen > 0 then
  begin
    Off := Length(PackedRegion);
    SetLength(PackedRegion, Off + PadLen);
    FillChar(PackedRegion[Off], PadLen, 0);
  end;

  if Length(MetaKey) > 0 then FillChar(MetaKey[0], Length(MetaKey), 0);
  if Length(State) > 0 then FillChar(State[0], Length(State), 0);

  InternalDebugLog(Format(
    'Região empacotada: %d bytes (%d chunks, %d de padding de alinhamento)',
    [Length(PackedRegion), N, PadLen]));
  Result := True;
end;

end.


