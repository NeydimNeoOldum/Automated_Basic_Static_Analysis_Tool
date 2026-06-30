rule UPX_Packed {
    strings:
        $s1 = "UPX0"
        $s2 = "UPX1"
    condition:
        $s1 and $s2
}

rule ASPack_Packed {
    strings:
        $s1 = "ASPack"
    condition:
        $s1
}

rule PECompact_Packed {
    strings:
        $s1 = "PEC2"
    condition:
        $s1
}

rule MPRESS_Packed {
    strings:
        $s1 = "MPRESS1"
    condition:
        $s1
}

rule Themida_Packed {
    strings:
        $s1 = "Themida"
    condition:
        $s1
}

rule VMProtect_Packed {
    strings:
        $s1 = "VMProtect"
    condition:
        $s1
}

rule Enigma_Packed {
    strings:
        $s1 = "enigma_46.dat"
    condition:
        $s1
}

rule FSG_Packed {
    strings:
        $s1 = "FSG!"
    condition:
        $s1
}

rule MEW_Packed {
    strings:
        $s1 = "MEW"
    condition:
        $s1
}

rule Petite_Packed {
    strings:
        $s1 = "Petite"
    condition:
        $s1
}

rule Armadillo_Packed {
    strings:
        $s1 = "Armadillo"
    condition:
        $s1
}

rule NsPack_Packed {
    strings:
        $s1 = "NsPack"
    condition:
        $s1
}

rule YodasCrypter_Packed {
    strings:
        $s1 = "Yoda's Crypter"
    condition:
        $s1
}

rule PELock_Packed {
    strings:
        $s1 = "PELock"
    condition:
        $s1
}

rule WinUpack_Packed {
    strings:
        $s1 = "UPACK"
    condition:
        $s1
}

rule ConfuserEx_Packed {
    strings:
        $s1 = "ConfuserEx"
    condition:
        $s1
}

rule InstallAware_Packed {
    strings:
        $s1 = "InstallAware"
    condition:
        $s1
}

rule DotNETReactor_Packed {
    strings:
        $s1 = ".NET Reactor"
    condition:
        $s1
}

rule Xenocode_Packed {
    strings:
        $s1 = "Xenocode"
    condition:
        $s1
}

rule Eziriz_NET_Reactor_Packed {
    strings:
        $s1 = "Eziriz .NET Reactor"
    condition:
        $s1
}

rule DNGuard_Packed {
    strings:
        $s1 = "DNGuard HVM"
    condition:
        $s1
}

rule Obsidium_Packed {
    strings:
        $s1 = "Obsidium"
    condition:
        $s1
}