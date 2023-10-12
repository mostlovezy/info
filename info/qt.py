from work import Plaintext,Ciphertext,IP,Inverse_IP,Key,P_10,P_8,left_shift,get_k1,get_k2,S_DES_fk
from PyQt5 import uic
import sys
import time
from PyQt5.QtCore import QThread,pyqtSignal
from  PyQt5.QtWidgets import QApplication
import numpy as np
import threading
import time
def task(s,e,p,c,result):
    k_lists=[]
    for i in range(s,e):
        k=bin(i)[2:].zfill(10)
        k_list=[a for a in k]
        plain_text=Plaintext(np.array([int(x) for x in p]))
        K=Key(length=10,key=np.array(k_list))
        after_IP=IP(plain_text)
        k1=get_k1(K)
        fk1=S_DES_fk(key=k1, text=after_IP)
        after_fk1AndSWAP=fk1.outputAfterSWAP()
        k2=get_k2(K)
        fk2=S_DES_fk(key=k2, text=after_fk1AndSWAP)
        after_fk2=fk2.output()
        after_inverseIP=Inverse_IP(after_fk2)
        cipher_text=Ciphertext(after_inverseIP.array)
        cipher_text=''.join(map(str, cipher_text.array))
        if cipher_text==c:
            k_lists.append(k)
            result.append(k)
    # return result       
        # print(k)
# task(0,10)
# print(f'明文:  {plain_text.array} \n开始加密: \n获得密文:  {cipher_text.array}')
class Lui:
    def __init__(self):
        # 从文件中加载UI定义
        self.ui = uic.loadUi("GUI.ui")
        self.bt1=self.ui.pushButton
        self.bt2=self.ui.pushButton_2
        self.bt3=self.ui.pushButton_3
        self.line1=self.ui.lineEdit
        self.line2=self.ui.lineEdit_2
        self.list1=self.ui.textEdit
        self.list2=self.ui.textEdit_2
        self.line3=self.ui.lineEdit_3
        self.line4=self.ui.lineEdit_4
        self.line5=self.ui.lineEdit_5
        self.line6=self.ui.lineEdit_6
        self.label=self.ui.textEdit_3
        self.bt1.clicked.connect(self.plain)
        self.bt2.clicked.connect(self.cipher)
        self.bt3.clicked.connect(self.force)
    def plain(self):
       #加密
        a=self.line1.text()
        aa=[]
        if ord(a[0])>57: 
            for x in a:
                aa.append(format(ord(x),"08b"))
        else:
                aa.append(a) 
        # print(self.line1.text())
        # self.list1.setText(self.line1.text())
        # print(aa)
        show=[]     
        # word=[]  
        K=Key(length=10,key=np.array([int(x) for x in self.line5.text()]))
        for a in aa:   
            plain_text=Plaintext(np.array([int(i) for i in a]))
            after_IP=IP(plain_text)
            k1=get_k1(K)
            fk1=S_DES_fk(key=k1, text=after_IP)
            after_fk1AndSWAP=fk1.outputAfterSWAP()
            k2=get_k2(K)
            fk2=S_DES_fk(key=k2, text=after_fk1AndSWAP)
            after_fk2=fk2.output()
            after_inverseIP=Inverse_IP(after_fk2)
            cipher_text=Ciphertext(after_inverseIP.array)
            iii=int(''.join(map(str, cipher_text.array)),2) #[0, 1, 0, 1, 1, 0, 0, 0]

            show.append(chr(iii))
        self.list1.setText(','.join(show))

    def cipher(self):
       #加密
        a=self.line2.text()
        aa=[]
        if ord(a[0])>57: 
            for x in a:
               aa.append(format(ord(x),"08b"))
        else:
               aa.append(a) 
        # show=np.array([])   
        show=[]     
        # word=[]  
        K=Key(length=10,key=np.array([int(x) for x in self.line6.text()]))
        for a in aa:          
            cipher_text=Ciphertext(np.array([int(i) for i in a]))
            # K=Key(length=10,key=np.array([1,0,0,0,1, 0,1,0,1,0]))
            after_IP=IP(cipher_text)
            k1=get_k1(K)
            k2=get_k2(K)
            fk2=S_DES_fk(key=k2, text=after_IP)
            after_fk2AndSWAP=fk2.outputAfterSWAP()
            fk1=S_DES_fk(key=k1, text=after_fk2AndSWAP)
            after_fk1=fk1.output()
            after_inverseIP=Inverse_IP(after_fk1)
            plain_text=Plaintext(after_inverseIP.array)
            show.append(''.join(map(str, plain_text.array)))
            # iii=int(''.join(map(str, plain_text.array)),2)
            # print(chr(iii))
            # word.append(chr(iii))
            # print(chr(int(''.join(map(str, plain_text.array)),2)))
        # print(word)  
        # show.append("\n字符串为：")
        # show.append(''.join(word))
        # print(show[-1])
        self.list2.setText(",".join(show))
    def force(self):
        # K=Key(length=10,key=np.array([int(x) for x in self.line6]))
        start_time=time.time()
        p=self.line3.text()  
        p=p if len(p)>1 else format(ord(p),"08b")
        c=self.line4.text()     
        c=c if len(c)>1 else format(ord(c),"08b")  
        threads=[]
        result=[]
        num=1024
        # print(num)
        peace=128
        result=[]
        for i in range(8):
            thread=threading.Thread(target=task,args=(i*peace,(i+1)*peace,p,c,result))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()    
        all_time=time.time()-start_time
        result.append(f"破解用时：{all_time:.6f}s")
        self.label.setText(",".join(result))    
        
        #     result.append(thread.result())
        # print(result)    
#子线程    
# class Mthread(QThread):
#   def __init__(self,amount,times):
#     super().__init__()
#     self.times=times
#     self.amount=amount
#     self.a=LiziGroup(self.amount,self.times) 
#     self.a.first_group_produce() 
#   signal = pyqtSignal(str)
#   def run(self):
#     for i in range(self.times):
#       self.a.update_group()
#       self.signal.emit(str(self.a.overall_min_hgraph))
#       # self.list.show()
#       time.sleep(0.1)
#     self.signal.emit("最小成本为:%f"%self.a.overall_min_cost)  
if  __name__=="__main__":
  app=QApplication(sys.argv)
  w=Lui()
  w.ui.show()
  app.exec()
