# -*- coding: utf-8 -*-
"""
Created on Sun Dec 24 10:41:36 2023

@author: HP
"""
from tkinter import*


root = Tk()
root.title('Camera Registration')
root.minsize(width= 640, height = 360)
root.maxsize(width= 1260, height = 720)
#root.config(bg='FFFFF')



lb1 = Label(text = 'Enter ID', width= 20 , height=1)
lb1.place(x = 160 , y = 100)

lb2 = Label(text = 'Enter Password', width= 20 , height=1, )
lb2.place(x = 160 , y = 140)

tb1 = Text(width= 20, height=1 )
tb1.place(x = 280, y = 100)

tb2 = Text(width= 20, height=1 )
tb2.place(x = 280, y = 140)

btn = Button(text ='Submit', bg = 'blue', fg = 'white')
btn.place(x = 300, y = 200)



root.mainloop()
