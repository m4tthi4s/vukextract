# vukextract
This is a small program to get VUK Keys from DVDFab.

## Installation
1. Download and install DVDFab from here: https://forum.dvdfab.cn/forumdisplay.php?f=70
2. Get the newest release of vukextract from here: https://github.com/m4tthi4s/vukextract/releases
  * You may have to compile it for yourself, if the needed binary is not available
3. Substitute in `~/DVDFab/dvdfab` at the bottom `$EXEC` with `exec $EXEC`
4. Verify if DVDFab is working correctly and proceed afterwards

## Usage
The keylines are always written to stdout and everything else to stderr, so you can pipe them to a `KEYDB.cfg` file via `| tee -a KEYDB.cfg`. I recommend backing up your existing file first.
At this moment two modes are implemented:
1. Attach to a DVDFab instance:
```bash
./vukextract --fab ~/DVDFab/dvdfab --log ~/Documents/DVDFab10/Log/dvdfab_internal.log | tee -a KEYDB.cfg
```
  * You have to provide the executeable with `--fab` and the logfile with `--log`
  * If you have a special eject for the disc drive you can specify it with `--eject_cmd "eject....."`
  
2. Search a dump-file given a disc_id:
```bash
./vukextract --dump "$filename" --discid "$discid" | tee -a KEYDB.cfg
```

## Contribution
Opening issues and creating pull-requests is welcomed.
