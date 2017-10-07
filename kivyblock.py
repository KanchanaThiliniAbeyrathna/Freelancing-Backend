import kivy
 
from kivy.app import App
from kivy.uix.gridlayout import GridLayout
from kivy.properties import BooleanProperty
from kivy.uix.button import Button
from kivy.config import Config
import subprocess
import time
import app
from threading import Timer

chainname = 'newchain'

si = subprocess.STARTUPINFO()
si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
si.wShowWindow = subprocess.SW_HIDE # default

Config.set('graphics', 'width', '500')
Config.set('graphics', 'height', '250')


class MyButton(Button):
    enabled = BooleanProperty(True)

    def on_enabled(self, instance, value):
        if value:
            self.background_color = [1,1,1,1]
            self.color = [1,1,1,1]
        else:
            self.background_color = [1,1,1,.3]
            self.color = [1,1,1,.5]

    def on_touch_down( self, touch ):
        if self.enabled:
            return super(self.__class__, self).on_touch_down(touch)

 
class blockGridLayout(GridLayout):
 
    # Function called when equals is pressed
    def calculate(self, calculation):
        if calculation:
            try:
                # Solve formula and display it in entry
                # which is pointed at by display
                self.display.text = str(eval(calculation))
            except Exception:
                self.display.text = "Error"
 
class BlockchainApp(App):
 
    def build(self):
        print(self)
        subprocess.Popen(['python.exe', 'app.py', 'htmlfilename.htm'], startupinfo=si)
        return blockGridLayout()

    def do_login(self, *args):
        subprocess.Popen(['python.exe', 'app.py', 'htmlfilename.htm'], startupinfo=si)
        subprocess.Popen("multichaind "+chainname+" -deamon", startupinfo=si)
        time.sleep(10)
        streams = ["projects","ProjectStatus", "contracts", "ContractStatus", "Users", "skills", "user-skill", "user-edu",
                   "user-portfolio", "user-work","user-review", "bid", "project_user_type", "ContractRules", "pubkeys"]
        for stream in streams:
            subprocess.Popen("multichain-cli " + chainname + " subscribe " + stream, startupinfo=si)
        time.sleep(10)

    def getStart(self):
        return "Blockchain Started Successfully"

    def getStop(self):
        return "Blockchain Stopped successfully"

    def stop(self, *args):
        subprocess.Popen("multichain-cli "+chainname+" stop", startupinfo=si)

 
blockApp = BlockchainApp()
blockApp.run()