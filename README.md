# apple_notes_export

## Overview
An easy-to-use tool to export all the notes from your Apple Notes database to markdown and csv files.

## How to use
### Preliminary
Please remember to **grant full disk access** to the terminal or IDE that you're using to run this script. 

Otherwise, the script won't get the authorization to access your apple notes database.
> 1. Go to > System Preference > Security & Privacy
> 
> 2. Select "Full Dish Access" in the left column and check the box beside the specific terminal or IDE that you're using

### Running the script
Use argument --directory to specify the path to save your markdown files.
If not specified, it would create a new directory called `notes` by default.
```
$ python3 notes_export.py
```
After running the command, there will be a prompt for you to input your password in case there are locked notes.

## Output
- Markdown files for each note, including its creation & modification date (under the subdirectory of its folder name)
- CSV files for notes metadata (under a `raw_data` sub-folder)