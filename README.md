# sink
sync any directory with 2 windows machines over your local network. <br>
no emailing yourself stuff. no cloud. no flash drives. no bs. <br>
<br>
_note_: this is still a _veeery_ big wip, as there are many features that I have planned to added; you can see this on the bottom of this readme.<br>
<br>
i built this to solve a specific problem: syncing files on a locked-down school laptop where python was one of the only things i was allowed to run.
## features
- automatically finds other computers running sink on your network
- you pick which devices to trust. no randoms can connect
- watches for changes and syncs them up near-instantly
- conflict handling; if you edit the same file in two places at once, or while the app isn't running, it saves both copies so you don't lose work. they'll be in a `.sink_conflicts` folder.

### ignoring files
if you have files or folders you *don't* want to sync (like `node_modules` or `__pycache__`), just create a file called `.sinkignore` in the same directory as the script.
it works just like a `.gitignore` file, just a bit more basic. add patterns of stuff to ignore, one per line. for example:
```
# ignore all .log files
*.log

# ignore a specific directory
/build/

# ignore files with a certain name
tempfile.tmp
```

the script will automatically pick up any changes to this file, no need to restart the entire thing.

## run ts
you know the drill
1. clone thy repo
2. install requirements.txt
3. cd to the repo, then simple run main.py
4. all syncing will occur in the same directory as main.py, in a folder called sync across both devices.
  
## boring stuff
wait is there no boring stuff?

## todo (with priority out of 5)
- UI (4)
- custom paths (5)
- encryption (5)
- system tray shenanigans (3)
- meshing with more than 2 devices (1)
