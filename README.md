# **UIU CTF - Reverse Engineering**

# Reject to Inject - 197 points

![](https://i.imgur.com/kzr9V9u.png)

> Attachment file: [IV.dll](https://2022.uiuc.tf/files/730b32097be5f04fd5ed3eda799901a0/IV.dll?token=eyJ1c2VyX2lkIjo5MTEsInRlYW1faWQiOjQ0OCwiZmlsZV9pZCI6NjM3fQ.YueAyA.EBvtH750spnAIjVK_1o9C-bl6aE)

![](https://i.imgur.com/bH7RQai.png)


Theo như kinh nghiệm rev windows của mình thì với file dll thì sẽ mở bằng IDA để static analysis trước:

Load file bằng IDA64:
Bật qua tab string, mình thấy một vài string đặt biệt như:

![](https://i.imgur.com/mkRHtyg.png)

Và một cái fake flag như này:

`uiuctf{sorry_im_just_a_fake_flag}`

Trace tới chổ gọi fake flag, ta có được hàm `sub_180013B90()` gọ tới nó:

```c
__int64 __fastcall sub_180013B90(const char *a1, _BYTE *a2)
{
  __int64 result; // rax
  int v3; // [rsp+24h] [rbp+4h]
  int v4; // [rsp+44h] [rbp+24h]
  int i; // [rsp+64h] [rbp+44h]
  int j; // [rsp+64h] [rbp+44h]
  const char *v7; // [rsp+88h] [rbp+68h]
  int v8; // [rsp+154h] [rbp+134h]

  sub_1800114B0(&unk_18002C161);
  sub_180011203((__int64)FakeFlag);
  sub_180011433((__int64)byte_180026590);
  v3 = j_strlen(a1);
  v4 = 5 * v3 / 8;
  v7 = a1;
  for ( i = 0; i < v3; ++i )
  {
    if ( a1[i] == byte_180026000 )
      a1[i] = byte_180026590[0];
  }
  for ( j = 0; j < v4; ++j )
  {
    v8 = j % 5;
    if ( j % 5 )
    {
      switch ( v8 )
      {
        case 1:
          a2[j] = ((int)byte_1800265C0[v7[2]] >> 4) | (2 * byte_1800265C0[v7[1]]) | ((byte_1800265C0[*v7] & 3) << 6);
          v7 += 2;
          break;
        case 2:
          a2[j] = ((int)byte_1800265C0[v7[1]] >> 1) | (16 * (byte_1800265C0[*v7] & 0xF));
          ++v7;
          break;
        case 3:
          a2[j] = ((int)byte_1800265C0[v7[2]] >> 3) | (4 * byte_1800265C0[v7[1]]) | ((byte_1800265C0[*v7] & 1) << 7);
          v7 += 2;
          break;
        case 4:
          a2[j] = byte_1800265C0[v7[1]] | (32 * (byte_1800265C0[*v7] & 7));
          v7 += 2;
          break;
      }
    }
    else
    {
      a2[j] = ((int)byte_1800265C0[v7[1]] >> 2) | (8 * byte_1800265C0[*v7]);
      ++v7;
    }
  }
  result = v4;
  a2[v4] = 0;
  return result;
}
```

Nhìn sơ qua thì đây có vẻ là hàm decrypt một đoạn data nào đó, tạm thời mình đặt tên nó là `decrypt()` tiếp tục trace xem hàm nào gọi cái này:

```c
__int64 __fastcall sub_180013260(HMODULE a1)
{
  char *v1; // rdi
  __int64 i; // rcx
  HANDLE CurrentProcess; // rax
  __int64 v4; // rdi
  char v6[32]; // [rsp+0h] [rbp-20h] BYREF
  char v7; // [rsp+20h] [rbp+0h] BYREF
  WCHAR ProfileDir[1034]; // [rsp+30h] [rbp+10h] BYREF
  int cchSize[9]; // [rsp+844h] [rbp+824h] BYREF
  HANDLE TokenHandle; // [rsp+868h] [rbp+848h] BYREF
  __int64 v11; // [rsp+888h] [rbp+868h]
  const char *Source; // [rsp+8A8h] [rbp+888h]
  const char *v13; // [rsp+8C8h] [rbp+8A8h]
  char Str1[1056]; // [rsp+8F0h] [rbp+8D0h] BYREF
  CHAR Filename[1044]; // [rsp+D10h] [rbp+CF0h] BYREF
  DWORD nSize; // [rsp+1124h] [rbp+1104h]
  int v17; // [rsp+1144h] [rbp+1124h]
  char v18[96]; // [rsp+1168h] [rbp+1148h] BYREF
  char Src[80]; // [rsp+11C8h] [rbp+11A8h] BYREF
  size_t MaxCount; // [rsp+1218h] [rbp+11F8h]
  CHAR Dst[472]; // [rsp+1240h] [rbp+1220h] BYREF
  char v22[1564]; // [rsp+1418h] [rbp+13F8h] BYREF
  unsigned int v23; // [rsp+1A34h] [rbp+1A14h]

  v1 = &v7;
  for ( i = 1300i64; i; --i )
  {
    *(_DWORD *)v1 = -858993460;
    v1 += 4;
  }
  sub_1800114B0(&unk_18002C0A0);
  memset(ProfileDir, 0, 0x800ui64);
  cchSize[0] = 2048;
  TokenHandle = 0i64;
  v11 = 0i64;
  Source = "\\Room2004";
  v13 = "\\sigpwnie.exe";
  memset(Filename, 0, 0x400ui64);
  nSize = 1024;
  v17 = 0;
  strcpy(v18, "IS7WXGC726Z9JZMFPOKWQVMEPJCSU2FIMAC5N2VYIPGFJPCZPROPMYNL");
  memset(Src, 0, 0x38ui64);
  MaxCount = 56i64;
  memset(Dst, 0, 0x1C0ui64);
  CurrentProcess = GetCurrentProcess();
  OpenProcessToken(CurrentProcess, 8u, &TokenHandle);
  GetUserProfileDirectoryW(TokenHandle, ProfileDir, (LPDWORD)cchSize);
  CloseHandle(TokenHandle);
  sub_18001147E(v22, 8i64);
  sub_18001144C(v22, ProfileDir);
  v11 = sub_180011343(v22);
  strcpy(Str1, v11);
  strcat(Str1, Source);
  strcat(Str1, v13);
  GetModuleFileNameA(0i64, Filename, nSize);
  v17 = strncmp(Str1, Filename, nSize);
  if ( v17 )
  {
    sub_180011221("Failed!\n");
    system("pause");
    FreeLibraryAndExitThread(a1, 0);
  }
  j_decrypt((__int64)v18, (__int64)Src);
  memccpy(Dst, Src, 125, MaxCount);
  v23 = MessageBoxA(0i64, Dst, "Success", 0);
  sub_18001141A(v22);
  v4 = v23;
  sub_1800113F2(v6, &unk_180021CA0);
  return v4;
}
```
Thì đây cũng là luồn thực thi chính của chương trình, mình đã đổi tên một số hàm cho dễ hiểu, còn các hàm còn lại tạm thời mình k cần quan tâm.

Thì flow rất dễ hiểu, chương trình check xem có phải mình đang thực thi nó ở đúng file và đường dẫn hay không, cụ thể là: 

`<user_profile_directory>\Room2004\sigpwnie.exe`

Nếu đúng nó sẽ decrypt cái đoạn v18:
`"IS7WXGC726Z9JZMFPOKWQVMEPJCSU2FIMAC5N2VYIPGFJPCZPROPMYNL"` và in `MessageBox`.

Vì file dll không thể chạy trực tiếp được nên đến đây có thể có nhiều hướng:

1. Build lại hàm decrypt và lấy flag
2. Viết 1 chương trình mới gọi tới dll và debug file dll lấy flag
3. Dùng rundll32.exe có sẵn của windows để load dll và debug bằng ida

Về cách thứ 1, lúc mình phân tích thì thấy một vài chổ của hàm decrypt gọi tới để genBytes như:

```c
__int64 __fastcall sub_180013FE0(unsigned int *a1)
{
  char *v1; // rdi
  __int64 i; // rcx
  char v4[32]; // [rsp+0h] [rbp-20h] BYREF
  char v5; // [rsp+20h] [rbp+0h] BYREF
  int v6[15]; // [rsp+28h] [rbp+8h] BYREF
  int j; // [rsp+64h] [rbp+44h]
  unsigned __int64 v8; // [rsp+138h] [rbp+118h]

  v1 = &v5;
  for ( i = 30i64; i; --i )
  {
    *(_DWORD *)v1 = -858993460;
    v1 += 4;
  }
  sub_1800114B0((__int64)&unk_18002C161);
  j = 0;
  j_memset(dword_180026670, 0, 0x40ui64);
  while ( j < 16 )
  {
    dword_180026670[j] = sub_180011177(*a1, (unsigned int)j);
    ++j;
  }
  sub_18001132F(dword_180026670);
  for ( j = 0; j < 100; ++j )
    sub_18001126C();
  v6[0] = -1678030491;
  v6[1] = 1213635701;
  v6[2] = 865493747;
  v6[3] = -1002882818;
  v6[4] = 52570913;
  v6[5] = 15408472;
  v6[6] = -277531332;
  v6[7] = 1883894447;
  v6[8] = 2049029407;
  v6[9] = -595920156;
  for ( j = 0; j < 10; ++j )
  {
    v8 = 4 * j;
    v6[v8 / 4] ^= sub_18001126C();
  }
  sub_18001155F(byte_180026590, 34i64, &unk_180021E58, v6);
  return sub_1800113F2(v4, &unk_180021D00);
}
```

Về chổ hàm `sub_18001126C()` được gọi riêng lẻ và dùng trực tiếp, rất có thể đây là hàm `rand()` và dùng `seed()` dựa trên fakeFlag lúc nãy, nên là việc build lại có vẻ khó, mình không làm theo cách này.

Mình dùng luôn cách 3 vì nó khá tiện lợi, tuy nhiên để debug thành công các bạn cần lưu ý 1 vài điểm như sau:

1. Đặt breakpoint đúng chổ:

Bản thân `rundll32.exe` sẽ load hàm của dll lên để thực thi, và để cho an toàn, ta nên đặt breakpoint ở đầu thân hàm, cụ thể:

![](https://i.imgur.com/Kchvh2m.png)

Hàm ta muốn thực thi sẽ là `sub_180013260()`

2. Setup debugger:

Tại debugger, chọn Select Debugger->Local Windows debugger

Debugger-> Process option mình setup như vầy:

![](https://i.imgur.com/DJcK4aA.png)

Vì mình từng sai chổ đặt breakpoint và setup parameters nên lúc đó mình stuck khá lâu mới có thể tìm đc cách giải quyết như này, xem như qua bài này mình biết thêm được vài điều và có thể debug dll dễ dàng.

> Lưu ý: Có thể chỉnh lại tuỳ theo directory, và bản thân hàm sub_180013260 cũng có thể khác mình.

Vậy là đã debug thành công.

![](https://i.imgur.com/WLlY50i.png)

Tại đoạn này, các bạn có thể bypass qua dễ dàng bằng cách thay đổi zeroFlag:

![](https://i.imgur.com/z0WhyhR.png)

![](https://i.imgur.com/0FmIr6q.png)

Ezflag:

![](https://i.imgur.com/iZtmIai.png)

Go on...

# Pierated Art - 311 points

![](https://i.imgur.com/u5w1QRQ.png)

Sau khi netcat tới địa chỉ ta được thông tin như sau:

![](https://i.imgur.com/4WAjPdy.png)

1 đoạn Torrented picture data bằng base 64 và nó kêu mình nhập flag (1/10) có nghĩa là 10 câu hỏi khác nhau và mỗi câu 15s.

Thử viết script lấy data về và chuyển thành ảnh:

```python
from pwn import *
p = remote("pierated-art.chal.uiuc.tf",1337)
p.recvuntil(b"(Base64):\n")
    dt = p.recvuntil(b"\n")
    dt = (dt.decode().strip('\n')).encode() 
    img_file = open('image.jpeg', 'wb')
    img_file.write(base64.b64decode(dt))
    img_file.close()
```

Run và mở `image.jpeg` lên ta được tấm ảnh như sau:

![](https://i.imgur.com/RQUrQmN.jpg)

Hoặc là như này:)))

![](https://i.imgur.com/fIVWxNf.jpg)

Và còn nhiều tấm khác nữa...

> Sao không thấy bức nào của ông Van Gogh nhờ:v

Tuy là khác nhau và có vẻ ngẫu nhiên nhưng các bạn có thể thấy ngay những điểm ảnh lạ trên hình và đặc biệt là phần góc trái trên cùng luôn có 1 đống pixel ảnh đầy màu sắc

![](https://i.imgur.com/Eb81lMc.png)

Sau khi tìm hiểu và nhận trợ giúp từ trùm forensic @PkNova thì mình biết được đây là `piet code`, link tham khảo [tại đây](https://esolangs.org/wiki/Piet).


> Piet is a stack-based esoteric programming language in which programs look like abstract paintings. 
It uses 20 colors, of which 18 are related cyclically through a lightness cycle and a hue cycle. 
A single stack is used for data storage, together with some unusual operations.

Hiểu cơ bản là nó sẽ chạy đoạn code thực thi dựa theo các pixel màu, cụ thể là những pixel lúc nãy, giờ cân 1 tool để chạy thử đoạn code đó.

@PkNova đưa minh cái này: https://www.bertnase.de/npiet/

Tải về và chạy thử 1 tấm ảnh lúc nãy:

![](https://i.imgur.com/Zik7cgq.png)

Rõ ràng đây là 1 chương trình nhỏ check flag, nhập bừa và xem thử:

![](https://i.imgur.com/jmnJnPX.png)

Chương trình xuất ra 0, nghĩa là flag sai. Dùng thử chức năng trace của npiet:

![](https://i.imgur.com/acVH7M3.png)

Ta sẽ lấy ra được toàn bộ code của chương trình và stack của nó trong lúc thực thi, rất hay.

Thử nhập `abcdefghijk` và sau đó là 1 đoạn code rất dài để check flag, và xuất ra output của chương trình là "0".

![](https://i.imgur.com/2WoiaQt.png)

Copy code và đưa vào code editor để rev,

Để ý thấy đoạn đầu của code sẽ là in ra từng kí tự của chuỗi "enter flag:?"

Và sau khi nhập input của mình vào, nó sẽ load từng kí tự của input lên stack, và bắt đầu đoạn check.

```
action: push, value 2
trace: stack (13 values): 2 1 105 104 103 102 101 100 99 98 97 195 96

trace: step 201  (983,608/d,l dC -> 983,609/d,l lC):
action: push, value 1
trace: stack (14 values): 1 2 1 105 104 103 102 101 100 99 98 97 195 96

trace: step 202  (983,609/d,l lC -> 983,610/d,l nY):
action: roll
trace: stack (12 values): 105 1 104 103 102 101 100 99 98 97 195 96

trace: step 203  (983,610/d,l nY -> 983,612/d,l dY):
action: push, value 22
trace: stack (13 values): 22 105 1 104 103 102 101 100 99 98 97 195 96

trace: step 204  (983,612/d,l dY -> 983,613/d,l dG):
action: add
trace: stack (12 values): 127 1 104 103 102 101 100 99 98 97 195 96

trace: step 205  (983,613/d,l dG -> 983,615/d,l lG):
action: push, value 26
trace: stack (13 values): 26 127 1 104 103 102 101 100 99 98 97 195 96

trace: step 206  (983,615/d,l lG -> 983,616/d,l nB):
action: mod
trace: stack (12 values): 23 1 104 103 102 101 100 99 98 97 195 96

trace: step 207  (983,616/d,l nB -> 983,617/d,l lR):
action: not
trace: stack (12 values): 0 1 104 103 102 101 100 99 98 97 195 96

trace: step 208  (983,617/d,l lR -> 983,618/d,l dY):
action: multiply
trace: stack (11 values): 0 104 103 102 101 100 99 98 97 195 96
trace: entering white block at 983,1193 (like the perl interpreter would)...
```

Và theo như mình rev được thì đây là 1 đoạn để check 1 kí tự của nó

Tạm thời không cần quan tâm đoạn push 2, push 1 và rool, Nó sẽ push 1 giá trị là `22` và cộng với kí tự của input (trong trường hợp này là 105, kí tự "i")

Và sau đó nó `mod` cho 26 và `not` lại ra trị vừa ra và nhân tiếp cho kết quả của đoạn check tiếp theo.

Thì để out put của chương trình là 1, đồng nghĩa với việc (kí tự nhập vào + n mod 26) = 0 (với n là số đề cho theo từng kí tự và <26) và lặp lại với tất cả các kí tự còn lại.

Vì đề bài cho password là lower case nên là trong trường hợp input thuộc [97,122] sẽ có 2 chổ mà khi cộng 1 số n<26 sẽ thoả điều kiện là 130 và 104.

Từ đây, mình thử lấy tất cả các số `n` của nó ra để tìm thử password:

```python
l = [22,19,26,16,7,11,9,4,20,7]
def conv(ls):
    s = ""
    for i in ls:
        if i<8:
            s+=chr(104-i)
        else:
            s+=chr(130-i)
    return s
print(conv(l)[::-1]) #output: andywarhol
```
> Vì cơ chế stack sẽ đảo chiều chuỗi nên output của mình phải đảo lại trước khi in ra

Thử nhập vào chương trình:

![](https://i.imgur.com/Wvc8MSL.png)

Vậy là password đã đúng, chương trình đã xuất ra 1.

Nhưng còn 1 vấn đề là, làm sao để viết 1 script python có thể thực thi được lệnh: `npiet-1.3a-win32>npiet.exe -t image.jpeg` để lấy source code, từ source code lấy được các số `n` và lấy được flag send ngược lại cho server?

Sau 1 khoảng thời gian, mình tìm hiểu rất nhiều module khác nhau như `subprocess`, `pwintools`,`os` thì mình thấy có 1 cái có thể dùng đc là subprocess.

Vậy giờ sau khi có ảnh, mình sẽ dùng subprocess để chạy npiet, và nhập bừa input (vì flag k phụ thuộc vào input), phần stdout sẽ được lưu vào file `source.txt`:

```python
import subprocess
    f = open("source.txt",'wb')
    print("type some thing:")
    subprocess.call(["npiet.exe",'-t','image.jpeg'],stdout=f)
    f.close()
    f = open("source.txt",'r').readlines()
    ls = []
    for i in range(len(f)):
        if f[i]=="action: roll\n" and f[i+4]!="action: duplicate\n" and f[i+4]!="action: out(char)\n":
            x = f[i+4]
            num = int(x.split()[-1])
            ls.append(num)
    p.sendline(conv(ls).encode()[::-1])
```

Đoạn này khá hay ở chổ là mình có thể dùng `sdtout` để lưu thằng output vào file python đang mở. Mình từng stuck rất lâu chổ này và may là mình hiểu ra được stdout nên đã dùng thử và thành công luôn:))

Thêm 1 đặc điểm để lấy được `n`(cái này là tuỳ cơ ứng biến thôi): Để ý rằng sau các lệnh roll 4 lệnh sẽ có chổ lấy `n`, ngoại trừ các lệnh đặc biệt kia.

Việc còn lại là đưa nó vào 10 vòng lặp và thực thi thôi, và đây là script hoàn chỉnh:

```python
from pwn import *
import base64

def conv(ls):
    s = ""
    for i in ls:
        if i<8:
            s+=chr(104-i)
        else:
            s+=chr(130-i)
    return s
p = remote("pierated-art.chal.uiuc.tf",1337)
for n in range(10):
    p.recvuntil(b"(Base64):\n")
    dt = p.recvuntil(b"\n")
    dt = (dt.decode().strip('\n')).encode() 
    img_file = open('image.jpeg', 'wb')
    img_file.write(base64.b64decode(dt))
    img_file.close()


    import subprocess
    f = open("source.txt",'wb')
    print("Type something: ",end ="")
    subprocess.call(["npiet.exe",'-t','image.jpeg'],stdout=f)
    f.close()
    f = open("source.txt",'r').readlines()
    ls = []
    for i in range(len(f)):
        if f[i]=="action: roll\n" and f[i+4]!="action: duplicate\n" and f[i+4]!="action: out(char)\n":
            x = f[i+4]
            num = int(x.split()[-1])
            ls.append(num)
    p.sendline(conv(ls).encode()[::-1])
    print(f"Password {n+1}/10 accepted!")
p.interactive()
```

![](https://i.imgur.com/7gHWQPZ.png)

Flag: `uiuctf{m0ndr14n_b3st_pr0gr4mm3r_ngl}`

