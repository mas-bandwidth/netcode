; The netcode roadmap: the data ROADMAP.md is generated from.
; Same shape as nova-sprint's docs/roadmap.sexp (internal/roadmapdoc's package comment):
; data, never evaluated. Edit this file, then regenerate ROADMAP.md with nova-sprint's
; generator, from a nova-sprint checkout at 8893dada (tools/roadmap left nova-sprint after it):
;   go build -o /tmp/roadmap ./tools/roadmap && (cd <this repo> && /tmp/roadmap --file docs/roadmap.sexp --out ROADMAP.md)
; Never edit ROADMAP.md by hand. Created 2026-11-12 with its first item.
(roadmap "v1"
 :title "netcode roadmap"
 :text "Planned work for netcode. Created on 2026-11-12 with its first item. Landed work is in git."

 :groups
 (
  (group "found-in-rocketnet" :title "Found while working on rocketnet"
   :text "Defects found in code this repository shares with rocketnet, recorded here to fix later.")
 )

 :items
 (
  (item "sodium-lock-dll-unload" :group "found-in-rocketnet" :area "sodium"
   :title "Windows: sodium's lock is never deleted, so unloading a DLL that contains it trips Application Verifier"
   :text "On Windows, sodium/sodium.c (line 1995) creates _sodium_lock as a CRITICAL_SECTION with InitializeCriticalSection on first use and never deletes it, so a game that loads the library in a DLL and unloads it gets Application Verifier stop Locks 0x201 (unloading a DLL containing an active critical section) on FreeLibrary. Upstream libsodium 1.0.22 has the same code; upstream master deletes the lock in DllMain for DLL builds only, which does not help a library linked statically into a game DLL. The fix: make it static SRWLOCK _sodium_lock = SRWLOCK_INIT with AcquireSRWLockExclusive and ReleaseSRWLockExclusive, which needs no init and no teardown; sodium never takes the lock recursively."
   :date "2026-11-12"
   :origin "Fixed in mas-bandwidth/rocketnet PR #1048, which has the same bundled sodium; recorded here on Glenn's instruction of 2026-11-12")
 ))
