/*
 * tests/run-attesttest.sh: the ACPI side of an AMD-style fTPM over QEMU's
 * tpm-crb.  Its start method (TPM2 table: 2, ACPI start) has the OS call
 * _DSM function 1 for every command; here, as the PSP's firmware would,
 * that is what makes the command run: it takes locality 0, sets the CRB
 * start bit, waits for the command to finish and gives the locality
 * back.  QEMU ignores the start bit without a locality, and the OS takes
 * none with this start method, so the start bit the OS sets too does
 * nothing, as with an fTPM, whose CRB registers are plain memory.  Each
 * start also writes 'S' to the isa-debugcon port, for the test to count.
 * OVMF drives tpm-crb directly before ExitBootServices and leaves
 * locality 0 assigned: _INI, which the OS evaluates before its first
 * command, gives it back, or the OS's own start bit would start a
 * command before _DSM does (and _DSM would then start the response as a
 * second one).
 */
DefinitionBlock ("", "SSDT", 2, "L4H", "FTPM", 1)
{
    Scope (\_SB)
    {
        Device (FTPM)
        {
            Name (_HID, "MSFT0101")
            Name (_STR, Unicode ("l4h test fTPM"))

            OperationRegion (CRBL, SystemMemory, 0xFED40000, 0x50)
            Field (CRBL, DWordAcc, NoLock, Preserve)
            {
                Offset (0x08),
                LCTL, 32,
                Offset (0x4C),
                STRT, 32,
            }
            OperationRegion (DBGP, SystemIO, 0x0402, 1)
            Field (DBGP, ByteAcc, NoLock, Preserve)
            {
                DBGC, 8,
            }

            Method (_INI, 0, NotSerialized)
            {
                // OVMF drives tpm-crb directly before ExitBootServices and
                // leaves locality 0 assigned; release it before the first
                // command so only _DSM can start one.
                LCTL = 2
            }

            Method (_DSM, 4, Serialized)
            {
                If (Arg0 == ToUUID ("6bbf6cab-5463-4714-b7cd-f0203c0368d4"))
                {
                    If (Arg2 == 0)
                    {
                        // Functions 0 and 1.
                        Return (Buffer () { 0x03 })
                    }
                    If (Arg2 == 1)
                    {
                        // Run the command, and give the locality back
                        // when it is done, so that only _DSM ever starts
                        // one (as with the PSP).
                        LCTL = 1
                        STRT = 1
                        While (STRT & 1)
                        {
                            Stall (50)
                        }
                        LCTL = 2
                        DBGC = 0x53
                        Return (0)
                    }
                }
                Return (Buffer () { 0x00 })
            }
        }
    }
}
