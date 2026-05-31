using System.Collections.Generic;
using System.IO;
using System.Linq;
using System;

struct SegmentInfo
{
    public uint RawOffset;
    public uint RawSize;
    public uint BaseRva;
}

class Inspector
{
    static readonly byte[] DOS_SIG = { 0x4D, 0x5A };
    static readonly byte[] NT_SIG = { 0x50, 0x45, 0x00, 0x00 };

    static void Stop()
    {
        Console.WriteLine("\n  [Enter]");
        Console.ReadLine();
    }

    static void Rule() =>
        Console.WriteLine("  " + new string('━', 58));

    static void Block(string caption)
    {
        Console.WriteLine();
        Rule();
        Console.WriteLine($"   ▸ {caption}");
        Rule();
    }

    static void Row(string key, string val) =>
        Console.WriteLine($"   {key,-32}  {val}");

    static string ReadCStr(BinaryReader br, uint pos)
    {
        long bookmark = br.BaseStream.Position;
        br.BaseStream.Seek(pos, SeekOrigin.Begin);
        var buf = new System.Text.StringBuilder();
        byte ch;
        while ((ch = br.ReadByte()) != 0) buf.Append((char)ch);
        br.BaseStream.Seek(bookmark, SeekOrigin.Begin);
        return buf.ToString();
    }

    static uint ResolveRva(List<SegmentInfo> segs, uint rva)
    {
        foreach (var seg in segs)
            if (rva >= seg.BaseRva && rva < seg.BaseRva + seg.RawSize)
                return rva - seg.BaseRva + seg.RawOffset;
        return 0;
    }

    static void Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (args.Length == 0)
        {
            Console.WriteLine("  Укажи путь к файлу первым аргументом.");
            Stop(); return;
        }

        string filePath = args[0];

        if (!File.Exists(filePath))
        {
            Console.WriteLine($"  Файл не найден: {filePath}");
            Stop(); return;
        }

        using var br = new BinaryReader(File.Open(filePath, FileMode.Open, FileAccess.Read));

        // DOS signature
        if (!br.ReadBytes(2).SequenceEqual(DOS_SIG))
        {
            Console.WriteLine("  Нет MZ-сигнатуры."); Stop(); return;
        }

        br.BaseStream.Seek(0x3C, SeekOrigin.Begin);
        br.BaseStream.Seek(br.ReadInt32(), SeekOrigin.Begin);

        // NT signature
        if (!br.ReadBytes(4).SequenceEqual(NT_SIG))
        {
            Console.WriteLine("  Нет PE-сигнатуры."); Stop(); return;
        }

        // File Header
        ushort cpuType = br.ReadUInt16();
        ushort segmentCount = br.ReadUInt16();
        br.BaseStream.Seek(12, SeekOrigin.Current);
        ushort optHeaderLen = br.ReadUInt16();
        ushort fileFlags = br.ReadUInt16();

        // Optional Header
        ushort peKind = br.ReadUInt16();
        bool pe32 = peKind == 0x010B;

        br.BaseStream.Seek(14, SeekOrigin.Current);
        uint entryRva = br.ReadUInt32();

        br.BaseStream.Seek(4, SeekOrigin.Current);
        ulong loadBase = pe32 ? br.ReadUInt32() : br.ReadUInt64();

        uint alignMem = br.ReadUInt32();
        uint alignDisk = br.ReadUInt32();

        br.BaseStream.Seek(16, SeekOrigin.Current);
        uint memSize = br.ReadUInt32();

        br.BaseStream.Seek(10, SeekOrigin.Current);
        ushort dllFlags = br.ReadUInt16();

        // Data Directory
        br.BaseStream.Seek(pe32 ? 24 : 40, SeekOrigin.Current);

        uint expRva = br.ReadUInt32(); uint expLen = br.ReadUInt32();
        uint impRva = br.ReadUInt32(); uint impLen = br.ReadUInt32();
        uint rsrcRva = br.ReadUInt32(); uint rsrcLen = br.ReadUInt32();
        br.BaseStream.Seek(16, SeekOrigin.Current);
        uint relRva = br.ReadUInt32(); uint relLen = br.ReadUInt32();

        br.BaseStream.Seek(80, SeekOrigin.Current);

        // Section table
        var segments = new List<SegmentInfo>();
        var segTable = new List<(string label, uint memSz, uint memAddr, uint diskSz, uint diskOff, string perms)>();

        for (int idx = 0; idx < segmentCount; idx++)
        {
            string label = System.Text.Encoding.ASCII.GetString(br.ReadBytes(8)).TrimEnd('\0');
            uint memSz = br.ReadUInt32();
            uint memAddr = br.ReadUInt32();
            uint diskSz = br.ReadUInt32();
            uint diskOff = br.ReadUInt32();
            br.BaseStream.Seek(12, SeekOrigin.Current);
            uint secFlags = br.ReadUInt32();

            segments.Add(new SegmentInfo { BaseRva = memAddr, RawSize = memSz, RawOffset = diskOff });

            string perms = "";
            if ((secFlags & 0x20000000) != 0) perms += "E";
            if ((secFlags & 0x40000000) != 0) perms += "R";
            if ((secFlags & 0x80000000) != 0) perms += "W";

            segTable.Add((label, memSz, memAddr, diskSz, diskOff, perms));
        }

        Console.WriteLine();
        Console.WriteLine($"   {Path.GetFileName(filePath)}");

        Block("ЗАГОЛОВОК");

        string cpuLabel = cpuType switch
        {
            0x014C => "x86 (32-bit)",
            0x8664 => "AMD64",
            0x0200 => "Intel x64",
            _ => $"0x{cpuType:X4}"
        };

        Row("Архитектура", cpuLabel);
        Row("Разрядность", pe32 ? $"32 bit  (0x{peKind:X4})" : $"64 bit  (0x{peKind:X4})");
        Row("Точка входа", $"0x{entryRva:X8}");
        Row("Базовый адрес", pe32 ? $"0x{loadBase:X8}" : $"0x{loadBase:X16}");
        Row("Размер в памяти", $"{memSize:N0} B");
        Row("Выравн. память", $"0x{alignMem:X8}");
        Row("Выравн. файл", $"0x{alignDisk:X8}");

        Block("ФЛАГИ");

        Console.WriteLine("   Характеристики:");
        if ((fileFlags & 0x0002) != 0) Console.WriteLine("   File is executable");
        if ((fileFlags & 0x0020) != 0) Console.WriteLine("   App can handle > 2gb addresses");
        if ((fileFlags & 0x2000) != 0) Console.WriteLine("   File is a DLL.");
        Console.WriteLine("   ");
        Console.WriteLine("   DLL Характеристики:");
        if ((dllFlags & 0x0020) != 0) Console.WriteLine("   Image can handle a high entropy 64-bit virtual address space");
        if ((dllFlags & 0x0040) != 0) Console.WriteLine("   DLL can move");
        if ((dllFlags & 0x0100) != 0) Console.WriteLine("   Image is NX compatible");
        if ((dllFlags & 0x4000) != 0) Console.WriteLine("   Guard CF");
        Console.WriteLine("   ");
        if (rsrcLen > 0) Console.WriteLine("   Есть ресурсы");
        if (relLen > 0) Console.WriteLine("   Есть релокации");

        Block("СЕКЦИИ");
        Console.WriteLine($"   {"№",-3} {"Имя",-10} {"Virt.sz",-12} {"Virt.addr",-13} {"Raw.sz",-12} {"Raw.off",-12} {"RWX"}");
        Console.WriteLine("   " + new string('╌', 68));

        for (int i = 0; i < segTable.Count; i++)
        {
            var (lbl, msz, maddr, dsz, doff, prm) = segTable[i];
            Console.WriteLine($"   {i,-3} {lbl,-10} {msz + "B",-12} {"0x" + maddr.ToString("X8"),-13} {dsz + "B",-12} {"0x" + doff.ToString("X8"),-12} {prm}");
        }

        Block("ИМПОРТЫ");

        if (impRva > 0)
        {
            uint descOffset = ResolveRva(segments, impRva);
            br.BaseStream.Seek(descOffset, SeekOrigin.Begin);

            // читаем дескрипторы импорта (по 20 байт каждый)
            while (true)
            {
                uint thunkRva = br.ReadUInt32(); // OriginalFirstThunk
                br.BaseStream.Seek(8, SeekOrigin.Current);
                uint namePtr = br.ReadUInt32(); // Name RVA
                br.BaseStream.Seek(4, SeekOrigin.Current);

                if (thunkRva == 0) break;

                string dllName = ReadCStr(br, ResolveRva(segments, namePtr));
                Console.WriteLine($"   ┌ {dllName}");

                long descPos = br.BaseStream.Position;
                uint thunkOffset = ResolveRva(segments, thunkRva);
                br.BaseStream.Seek(thunkOffset, SeekOrigin.Begin);

                int fnIdx = 1;
                while (true)
                {
                    // в PE32+ thunk-записи 8 байт, в PE32 - 4
                    ulong entry = pe32 ? br.ReadUInt32() : br.ReadUInt64();
                    if (entry == 0) break;

                    bool byOrdinal = pe32
                        ? (entry & 0x80000000) != 0
                        : (entry & 0x8000000000000000) != 0;

                    if (byOrdinal)
                    {
                        ushort ordinal = (ushort)(entry & 0xFFFF);
                        Console.WriteLine($"   │  {fnIdx,4}.  #{ordinal}");
                    }
                    else
                    {
                        // hint (2 байта) + имя функции
                        uint hintRva = (uint)(entry & 0x7FFFFFFF);
                        uint hintOff = ResolveRva(segments, hintRva);
                        long markFn = br.BaseStream.Position;
                        br.BaseStream.Seek(hintOff + 2, SeekOrigin.Begin); // пропускаем hint
                        var fnSb = new System.Text.StringBuilder();
                        byte fc;
                        while ((fc = br.ReadByte()) != 0) fnSb.Append((char)fc);
                        br.BaseStream.Seek(markFn, SeekOrigin.Begin);
                        Console.WriteLine($"   │  {fnIdx,4}.  {fnSb}");
                    }

                    fnIdx++;
                }

                Console.WriteLine("   │");
                br.BaseStream.Seek(descPos, SeekOrigin.Begin);
            }
        }
        else Console.WriteLine("   Таблица импортов пуста");

        Block("ЭКСПОРТЫ");

        if (expRva > 0)
        {
            br.BaseStream.Seek(ResolveRva(segments, expRva), SeekOrigin.Begin);

            br.BaseStream.Seek(12, SeekOrigin.Current);
            uint ownNamePtr = br.ReadUInt32();
            br.BaseStream.Seek(8, SeekOrigin.Current);
            uint funcCount = br.ReadUInt32();
            br.BaseStream.Seek(4, SeekOrigin.Current);
            uint nameListPtr = br.ReadUInt32();

            Console.WriteLine("   " + ReadCStr(br, ResolveRva(segments, ownNamePtr)));
            Console.WriteLine();

            br.BaseStream.Seek(ResolveRva(segments, nameListPtr), SeekOrigin.Begin);

            for (int i = 0; i < funcCount; i++)
            {
                uint fnPtr = br.ReadUInt32();
                long mark = br.BaseStream.Position;
                string fnName = ReadCStr(br, ResolveRva(segments, fnPtr));
                br.BaseStream.Seek(mark, SeekOrigin.Begin);
                Console.WriteLine($"   {i + 1,4}  {fnName}");
            }
        }
        else Console.WriteLine("   Таблица экспортов пуста");

        Console.WriteLine();
        Rule();

        Stop();
    }
}