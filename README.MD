
# Password, Please?

A crappy but _hopefully_ safe terminal-based password manager!

> [!WARNING]
> If you intend to use a password manager, opt for a reputable software instead of cloning it from a small GitHub project


## Requirements

- python 3.7 or above


## Installation
1. Clone the repository:
    ```sh
    git clone "https://github.com/KaindraDjoemena/please"
    cd please
    ```
2. Setup and use your virtual environment:
    #### Windows
    ```sh
    python -m venv venv
    venv\Scripts\activate
    ```

    #### Unix-like systems
    ```sh
    python3 -m venv venv
    source venv/bin/activate
    ```

3. Install dependencies
    #### Windows
    ```sh
    pip install --editable .
    ```

    #### Unix-like systems
    ```sh
    pip3 install --editable .
    ```

4. (Optional) Add the application to your system PATH
    #### Windows
    1. Search for "Edit environment variables for your account"
    2. Click on the Environment Variables button
    3. Select "Path" under the System variables section
    4. Click on the "Edit" button
    5. Click on the "New" button
    6. Paste the absolute path for the pls.exe folder
    7. Click on the "OK" button to apply the changes
    8. Restart your terminal
    
    #### pls.exe is in \venv\Scripts\pls.exe

    #### Unix-like systems
    ```sh
    echo 'export PATH="<file_location>:$PATH"' >> ~/.bashrc
    ```
    #### *Replace <file_location> with the absolute path of the ```pls``` executable

## Usage

### Starting up the app
```sh
pls
```

> [!NOTE]
> You can execute ```pls``` anywhere if you've added it to PATH. You'll need to activate the venv every time if you haven't

### Interface Controls
#### Row navigation
| command | key
|-|:-:
| UP | k / `UP_ARROW`
| DOWN | j / `DOWN_ARROR`
| LEFT | j / `LEFT_ARROW`
| RIGHT | l / `RIGHT_ARROW`
| CONFIRMATION | `ENTER`


## Future Improvements
- **Horrible code structure**: too many repeating and/or unstructured code
- **Noticable subpar performance**: depending on the machine, the program starts to slow down pretty quickly
- **Interface**: don't think the interface is good enough. Looks pretty cluttered

#### Questions/Feedback: [@threepinchesofsalt](https://www.instagram.com/threepinchesofsalt?utm_source=ig_web_button_share_sheet&igsh=ZDNlZDc0MzIxNw==)


## License
[MIT](https://choosealicense.com/licenses/mit/)


## Thank you <3
Thank you for using Please!