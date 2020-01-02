ISB = (
            0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
            0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
            0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
            0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
            0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
            0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
            0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
            0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
            0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
            0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
            0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
            0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
            0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
            0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
            0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D)


class AES:
	state=0
	full_key=[]
        Sbox =  (   0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67,
	            0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59,0x47, 0xf0, 0xad, 0xd4,
		    0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7,0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 
		    0xa5, 0xe5, 0xf1,0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
		    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b,0x6e, 0x5a,
		    0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29,0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc,
		    0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43,
		    0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c,
	            0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc,
	            0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
	            0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19,
	            0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee,
	            0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49,
	            0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
	            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4,
	            0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6,
	            0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70,
	            0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9,
	            0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e,
	            0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1,
	            0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16)

	rcon=[0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]
	def keyEx(self,key):
		self.full_key.append(key)
		for key_index in range(10):
			last_col=[]
			for j in range(4):
				last_col.append(self.full_key[key_index][3][j])
			last_col[0],last_col[1],last_col[2],last_col[3]=last_col[1],last_col[2],last_col[3],last_col[0]	
			for j in range(4):
				last_col[j]=self.Sbox[last_col[j]]
			prev_col=[]
			working_col=[]
			temp_exp_key=[]
			for i in range(4):
				prev_col.append(self.full_key[key_index][0][i])
			working_col.append(last_col[0]^prev_col[0]^self.rcon[key_index])
			for i in range(3):
				working_col.append(last_col[i+1]^prev_col[i+1])
			temp_exp_key.append(working_col)
			for i in range(3):
				prev_col=[]
				last_col=working_col
				working_col=[]
				for j in range(4):
					prev_col.append(self.full_key[key_index][i+1][j])
				for j in range(4):
					working_col.append(prev_col[j]^last_col[j])
				temp_exp_key.append(working_col)
			self.full_key.append(temp_exp_key)
		'''print "The expanded key is as below:: "
		for index in range(11):
			print str(index)+" :  ",
			for i in range(4):                        //this is not required
				for j in range(4):
					print hex(self.full_key[index][i][j])[2:],
			print"\n"
		'''
	def keyWhitening(self):
		for i in range(4):
			for j in range(4):
				self.state[i][j]^=self.full_key[0][i][j]
		
			
	def shiftRow(self):
		self.state[0][1],self.state[1][1],self.state[2][1],self.state[3][1]=self.state[1][1],self.state[2][1],self.state[3][1],self.state[0][1]
		self.state[0][2],self.state[1][2],self.state[2][2],self.state[3][2]=self.state[2][2],self.state[3][2],self.state[0][2],self.state[1][2]
		self.state[0][3],self.state[1][3],self.state[2][3],self.state[3][3]=self.state[3][3],self.state[0][3],self.state[1][3],self.state[2][3]		
	def subByte(self):
		for i in range(4):
			for j in range(4):
				self.state[i][j]=self.Sbox[self.state[i][j]]
	def vecMulGF(self,column,j):
		if(j==0):
			if(column[0]&0x80==0x80 and column[1]&0x80==0x80):
				val=column[1]
				value=((2*column[0] ^ 0x1b) ^ (2*column[1] ^ 0x1b ^ val) ^ column[2] ^ column[3])%256		
			elif(column[0]&0x80==0x80 and column[1]&0x80==0x00):
				val=column[1]
				value=((2*column[0] ^ 0x1b) ^ (2*column[1] ^ val) ^ column[2] ^ column[3])%256
			elif(column[0]&0x80==0x00 and column[1]&0x80==0x80):
				val=column[1]
				value=(2*column[0] ^ (2*column[1] ^ 0x1b ^ val) ^ column[2] ^ column[3])%256
			elif(column[0]&0x80==0x00 and column[1]&0x80==0x00):
				val=column[1]
				value=(2*column[0] ^ (2*column[1] ^ val) ^ column[2] ^ column[3])%256
			return value
		if(j==1):
			if(column[1]&0x80==0x80 and column[2]&0x80==0x80):
				val=column[2]
				value=((2*column[1] ^ 0x1b) ^ (2*column[2] ^ 0x1b ^ val) ^ column[0] ^ column[3])%256		
			elif(column[1]&0x80==0x80 and column[2]&0x80==0x00):
				val=column[2]
				value=((2*column[1] ^ 0x1b) ^ (2*column[2] ^ val) ^ column[0] ^ column[3])%256
			elif(column[1]&0x80==0x00 and column[2]&0x80==0x80):
				val=column[2]
				value=(2*column[1] ^ (2*column[2] ^ 0x1b ^ val) ^ column[0] ^ column[3])%256
			elif(column[1]&0x80==0x00 and column[2]&0x80==0x00):
				val=column[2]
				value=(2*column[1] ^ (2*column[2] ^ val) ^ column[0] ^ column[3])%256
			return value
		if(j==2):
			if(column[2]&0x80==0x80 and column[3]&0x80==0x80):
				val=column[3]
				value=((2*column[2]^ 0x1b) ^ (2*column[3] ^ 0x1b ^ val) ^ column[0] ^ column[1])%256		
			elif(column[2]&0x80==0x80 and column[3]&0x80==0x00):
				val=column[3]
				value=((2*column[2] ^ 0x1b) ^ (2*column[3] ^ val) ^ column[0] ^ column[1])%256
			elif(column[2]&0x80==0x00 and column[3]&0x80==0x80):
				val=column[3]
				value=(2*column[2] ^ (2*column[3] ^ 0x1b ^ val) ^ column[0] ^ column[1])%256
			elif(column[2]&0x80==0x00 and column[3]&0x80==0x00):
				val=column[3]
				value=(2*column[2] ^ (2*column[3] ^ val) ^ column[0] ^ column[1])%256
			return value
		if(j==3):		
			if(column[3]&0x80==0x80 and column[0]&0x80==0x80):
				val=column[0]
				value=((0x1b^2*column[3]) ^ (0x1b^2*column[0] ^ val) ^ column[1] ^ column[2])%256
			elif(column[3]&0x80==0x80 and column[0]&0x80==0x00):
				val=column[0]
				value=((2*column[3]^0x1b) ^ (2*column[0] ^ val) ^ column[1] ^ column[2])%256
			elif(column[3]&0x80==0x00 and column[0]&0x80==0x80):
				val=column[0]
				value=(2*column[3] ^ (2*column[0]^0x1b^ val) ^ column[1] ^ column[2])%256
			elif(column[3]&0x80==0x00 and column[0]&0x80==0x00):
				val=column[0]
				value=(2*column[3] ^ (2*column[0] ^ val) ^ column[1] ^ column[2])%256	
			return value
				    		
	def mixColumn(self):
		for i in range(4):
			temp=[]
			for j in range(4):
				a=self.vecMulGF(self.state[i],j)
				temp.append(a)
			self.state[i]=temp
	
	def addRoundKey(self,key_index):
		for i in range(4):
			for j in range(4):
				self.state[i][j]^=self.full_key[key_index][i][j]
	def display(self):
		for i in range(4):			
			for j in range(4):
				print hex(self.state[j][i])[2:],
			print "\n"	

	'''	
	def encrypt(self,state,key,fault):
		self.state=state
		self.keyEx(key)
		self.keyWhitening()
		for i in range(9):
			#print "\nI AM IN %d STEP::"%(i+1)
			self.subByte()
			self.shiftRow()
			self.mixColumn()
			#print "\nAfte MixColumn: "
			#self.display()
			self.addRoundKey(i+1)
		self.subByte()
		self.shiftRow()			
		self.addRoundKey(10)
		return self.state
	'''
def xorsum(state1,state2):
	for i in range(4):
		for j in range(4):
			print hex(state1[j][i]^state2[j][i])[2:],
		print "\n"



import copy
print "Sbox=%d"%AES.Sbox[82]
print "Sbox=%d"%AES.Sbox[83]

#creating a object enc to class encrypt..
faulty_cipher=AES()
fault_free_cipher=AES()
#faulty=AES()
state=[[0x54,0x77,0x6f,0x20],[0x4f,0x6e,0x65,0x20],[0x4e,0x69,0x6e,0x65],[0x20,0x54,0x77,0x6f]]
key=[[0x54,0x68,0x61,0x74],[0x73,0x20,0x6d,0x79],[0x20,0x4b,0x75,0x6e],[0x67,0x20,0x46,0x75]]
#performing encryption
#pass value 1 to occur fault
faulty_cipher.state=copy.deepcopy(state)
fault_free_cipher.state=state
faulty_cipher.keyEx(key)
fault_free_cipher.keyEx(key)
faulty_cipher.keyWhitening()
fault_free_cipher.keyWhitening()
for i in range(9):
	if(i<7):
		faulty_cipher.subByte()
		fault_free_cipher.subByte()
		faulty_cipher.shiftRow()
		fault_free_cipher.shiftRow()
		faulty_cipher.mixColumn()
		fault_free_cipher.mixColumn()
		faulty_cipher.addRoundKey(i+1)
		fault_free_cipher.addRoundKey(i+1)
	elif(i>=7):
		# before fault the state matrix shapes
		#fault_free_cipher.display()
		#faulty_cipher.display()
		if i==7:
			###inducing the fault at 8th round input###
			#print faulty_cipher.state
			faulty_cipher.state[0][0]=0x52
			print "subbyte fault free "+str(hex(AES.Sbox[0x53]))
			print "subbyte fault faulty "+str(hex(AES.Sbox[0x52]))
		faulty_cipher.subByte()
		fault_free_cipher.subByte()
		print "After %ith round subByte: "%(i+1)
		xorsum(faulty_cipher.state,fault_free_cipher.state)
		faulty_cipher.shiftRow()
		fault_free_cipher.shiftRow()
		print "After %ith round shiftRow: "%(i+1)
		xorsum(faulty_cipher.state,fault_free_cipher.state)
		faulty_cipher.mixColumn()
		fault_free_cipher.mixColumn()
		print "After %ith round mixColumn: "%(i+1)
		xorsum(faulty_cipher.state,fault_free_cipher.state)
		faulty_cipher.addRoundKey(i+1)
		fault_free_cipher.addRoundKey(i+1)
		print "After %dth round ARK: "%(i+1)
		xorsum(faulty_cipher.state,fault_free_cipher.state)
faulty_cipher.subByte()
fault_free_cipher.subByte()
print "After %dth round subByte: "%(10)
xorsum(faulty_cipher.state,fault_free_cipher.state)
faulty_cipher.shiftRow()
fault_free_cipher.shiftRow()
print "After %dth round shiftRow: "%(10)
xorsum(faulty_cipher.state,fault_free_cipher.state)
faulty_cipher.addRoundKey(10)
fault_free_cipher.addRoundKey(10)
print "After %dth round ARK: "%(10)
xorsum(faulty_cipher.state,fault_free_cipher.state)
#############################################################################################

#print"Faulty Cipher:: "
#faulty_cipher.display()
#print"Faultfree Cipher:: "
#fault_free_cipher.display()
faulty_cipher=copy.deepcopy(faulty_cipher.state)
fault_free_cipher=copy.deepcopy(fault_free_cipher.state)
######################### Performing the attack ##########################
##         key_00 --> key_13
val_00=[]
val_13=[]
for i in range(256):
	val_00.append(ISB[fault_free_cipher[0][0]^i]^ISB[faulty_cipher[0][0]^i])
	temp=ISB[fault_free_cipher[3][1]^i]^ISB[faulty_cipher[3][1]^i]
	if(temp&0x80==0x80):
		val_13.append((0x1b^2*temp)%256)
	elif(temp&0x80==0x00):
		val_13.append(2*temp)	
	
reduced_key_map_00_13=[]		
count=0
for i in range(len(val_00)):
	for j in range(len(val_13)):
		if(val_00[i]==val_13[j]):
			reduced_key_map_00_13.append([])
			reduced_key_map_00_13[count].append(i)
			reduced_key_map_00_13[count].append(j)
			count+=1


##         key_13 --> key_22
val_13=[]
val_22=[]
for i in range(256):
	val_13.append(ISB[fault_free_cipher[3][1]^i]^ISB[faulty_cipher[3][1]^i])
	val_22.append(ISB[fault_free_cipher[2][2]^i]^ISB[faulty_cipher[2][2]^i])

reduced_key_map_13_22=[]
count=0
for i in range(len(val_13)):
	for j in range(len(val_22)):
		if(val_13[i]==val_22[j]):
			reduced_key_map_13_22.append([])
			reduced_key_map_13_22[count].append(i)
			reduced_key_map_13_22[count].append(j)
			count+=1



##         key_13 --> key_31
val_13=[]
val_31=[]
for i in range(256):
	val_31.append(ISB[fault_free_cipher[1][3]^i]^ISB[faulty_cipher[1][3]^i])
	temp=ISB[fault_free_cipher[3][1]^i]^ISB[faulty_cipher[3][1]^i]
	if(temp&0x80==0x80):
		val_13.append((0x1b^2*temp^temp)%256)
	elif(temp&0x80==0x00):
		val_13.append(2*temp^temp)	

reduced_key_map_13_31=[]		
count=0
for i in range(len(val_13)):
	for j in range(len(val_31)):
		if(val_13[i]==val_31[j]):
			reduced_key_map_13_31.append([])
			reduced_key_map_13_31[count].append(i)
			reduced_key_map_13_31[count].append(j)
			count+=1


#print reduced_key_map_00_13
#print reduced_key_map_13_22
#print reduced_key_map_13_31
col_1=[]
for i in range(len(reduced_key_map_00_13)):
	col_1.append(reduced_key_map_00_13[i])
	for j in range(len(reduced_key_map_13_22)):
		if (reduced_key_map_00_13[i][1]==reduced_key_map_13_22[j][0]):
			if len(col_1[i])==2:
				col_1[i].append(reduced_key_map_13_22[j][1])
			elif len(col_1[i])==3:
				col_1.append(col_1[i][:2])
				col_1[len(col_1)-1].append(reduced_key_map_13_22[j][1])

#here we are removing the unnecessary 2 length options
col_1_copy = copy.deepcopy(col_1)
for i in range(len(col_1)):
	if (len(col_1[i])==2):
		col_1_copy.remove(col_1[i])
#col_1_copy contains byte mapped values 00-13-22
#below we will add 31 byte with it, considering the 13-31 relation
for i in range(len(col_1_copy)):
	for j in range(len(reduced_key_map_13_31)):
		if(col_1_copy[i][1]==reduced_key_map_13_31[j][0]):
			if (len(col_1_copy[i])==3):
				col_1_copy[i].append(reduced_key_map_13_31[j][1])
			elif(len(col_1_copy[i])==4):
				col_1_copy.append(col_1_copy[i][:3])
				col_1_copy[len(col_1_copy)-1].append(reduced_key_map_13_31[j][1])

#print col_1_copy
#print len(col_1_copy)
col_1=copy.deepcopy(col_1_copy)
for i in range(len(col_1_copy)):
	if(len(col_1_copy[i])==3):
		col_1.remove(col_1_copy[i])
for item in col_1:
	#print hex(item[0])+" "+hex(item[1])+" "+hex(item[2])+" "+hex(item[3])
	if (item[0]==0x54 and item[1]==0x20 and item[2]==0x75 and item[3]==0x79):
		print "FOUND"
