import subprocess
import time
import sys

def run_automation():
    # main.py ko start karein
    # Agar main.py kisi aur folder me hai, to yahan uska pura path dein
    process = subprocess.Popen(
        [sys.executable, "bot.py"], 
        stdin=subprocess.PIPE, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.STDOUT, 
        text=True,
        bufsize=1 # Line by line output read karne ke liye
    )

    print("[-] main.py start ho gaya hai...")

    try:
        # Main.py ke output ko continuously read karein
        for line in iter(process.stdout.readline, ''):
            # Output ko console par print karein taaki aapko pata chale kya ho raha hai
            print(line, end='')
            
            # 1. Check karein ki kya MENU aaya hai
            if "MAIN MENU" in line or "> " in line:
                time.sleep(0.5) # Thoda wait karein taaki menu poora load ho jaye
                print("\n[AUTO] Command '3' bhej raha hai...")
                process.stdin.write("3\n")
                process.stdin.flush()
                
            # 2. Check karein ki kya Region select karne ka time aaya hai
            elif "Choose Match Region" in line or "Starting match in region" in line:
                time.sleep(0.5)
                print("\n[AUTO] Command '1' bhej raha hai...")
                process.stdin.write("1\n")
                process.stdin.flush()

            # 3. Check karein ki kya Match khatam hone ka message aaya hai
            elif "Press Enter to continue" in line:
                time.sleep(1) # Match khatam hone ke baad thoda wait
                print("\n[AUTO] Enter press kar raha hai...")
                process.stdin.write("\n")
                process.stdin.flush()

    except KeyboardInterrupt:
        print("\n[-] Automation rok diya gaya.")
        process.terminate()
    except Exception as e:
        print(f"Error: {e}")
        process.terminate()

if __name__ == "__main__":
    run_automation()