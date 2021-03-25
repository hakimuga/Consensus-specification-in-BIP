@cpp(src="ext-cpp/utilities.cpp,ext-cpp/trace_helper.cpp,ext-cpp/proba_helper.cpp",include="utilities.hpp,trace_helper.hpp,proba_helper.hpp")

package pbft
  extern function printf(string, int, int)
  extern function printf(string, float, float ,float)
  extern function printf(string, int, float)
  extern function printf(string, float, float)
  extern function printf(string, int, int,int)
  extern function printf(string,int)
  extern function printf(string,float)

 //changing the view where input : (id current node, max node)  output: new view
  extern function int modulo( int, int) 
  extern function int readBlock(  ) 
  extern function int checkBlock( int ) 


  port type Port_t()
  port type Port_blockreader( int BLOCK)
  port type Port_elected( int PRIMARY_NODE ,int NETWORK_VIEW)
  port type Port_preprepare( int BLOCK  )
  port type Port_prepare(   )
  port type Port_commit(   )
  port type Port_reply(   )
  port type Port_faulty(   )

  port type Port_viewchange(   )

  port type Port_update( int DEVICE_ID, int  VALUE )
  port type Port_read( int DEVICE_ID, int  VALUE )
  port type Port_create( int DEVICE_ID, int  VALUE )
  port type Port_all( int DEVICE_ID, int  VALUE )
  port type Port_ordererBlock( int BLOCK  )
  port type Port_ordererVALUE( int VALUE  )

atom type Device ( int id )
 data int DEVICE_ID
 data int VALUE
 data int GUARD

 port Port_t p0()
 port Port_t p1()
 export port Port_update updateValue(  DEVICE_ID,  VALUE)

 place START,  UPDATE

 initial to START do { GUARD = 1; DEVICE_ID = id; 	printf("var int device %d\n",  DEVICE_ID);}
 on  p0  from START  to UPDATE provided (GUARD >0 ) do { GUARD = GUARD - 1 ; VALUE = 5 ;}
 on  updateValue  from UPDATE  to START do { printf("var int DEVICE %d  IS BRODCASTING VALUE %d \n",  DEVICE_ID, VALUE ); }

end

//connector
connector type connupdateValue(Port_update device, Port_update smart)
  define device smart
  on device smart  down { smart.DEVICE_ID =device.DEVICE_ID;  smart.VALUE =device.VALUE;}
end
connector type connreadValue(Port_read device, Port_read smart)
  define device smart
end
connector type conncreateValue(Port_create device, Port_create smart)
  define device smart
end
connector type connallValue(Port_all device, Port_all smart)
  define device smart
end 
connector type connordererBlock(Port_ordererBlock device, Port_ordererBlock smart)
  define device smart
  on device smart  down { smart.BLOCK =device.BLOCK;}
end
connector type connordererVALUE(Port_ordererVALUE device, Port_ordererVALUE smart)
  define device smart
  on device smart  down { smart.VALUE =device.VALUE;}
end

atom type Acl( )
 data int DEVICE_ID
 data int VALUE

 data int GUARD

 data int UPDATE
 data int READ
 data int CREATE
 data int ALL
 data int DENY
 data int ALLOW

 port Port_t p0()
 port Port_t p1()
 port Port_t p2()
 export port Port_update updateValue (  DEVICE_ID,  VALUE )
 export port Port_read    readValue ( DEVICE_ID,  VALUE)
 export port Port_create createValue ( DEVICE_ID,  VALUE)
 export port Port_all       allValue ( DEVICE_ID,  VALUE )
 export port Port_ordererVALUE ordererVALUE( VALUE  )

 place START, OPERATION, ACTION, END
 
 initial to START do { UPDATE = 0; READ = 0; CREATE=0; ALL=0; DENY=0; ALLOW=0;}
 on updateValue from START to OPERATION       do { UPDATE = 1; printf("var int ACL IS RECEIVING VALUE %d FOR UPDATE \n",  VALUE );}
 on readValue    from START to OPERATION       do { READ = 1; printf("var int ACL IS RECEIVING VALUE %d FOR READ \n",  VALUE );}
 on createValue from START to OPERATION       do { CREATE = 1; printf("var int ACL IS RECEIVING VALUE %d FOR CREATE \n",  VALUE );}
 on allValue       from START to OPERATION       do { ALL = 1; printf("var int ACL IS RECEIVING VALUE %d FOR ALL \n",  VALUE );}

 on p0 from OPERATION to ACTION do {
			if (DEVICE_ID==0 && UPDATE==1 ) then ALLOW=1; DENY=0; fi 
			if (DEVICE_ID !=0 && UPDATE==1 ) then DENY  =1;  ALLOW=0; fi 

}
//ordererBlock
 on ordererVALUE from ACTION to START provided (ALLOW ==1) do { 
		printf("var int ACL IS ALLOWING DEVICE ACCESS %d FOR ACTION \n",DEVICE_ID,  VALUE );
		printf("var int d.%d.allow %d\n",  DEVICE_ID, ALLOW );
		printf("var int d.%d.deny %d\n",  DEVICE_ID, DENY );
UPDATE = 0; READ = 0; CREATE=0; ALL=0; DENY=0; ALLOW=0;
		}

 on p1 from ACTION to START provided (DENY   ==1) do {
		printf("var int ACL IS DENYING DEVICE ACCESS %d FOR ACTION \n",DEVICE_ID,  VALUE );
		printf("var int d.%d.allow %d\n",  DEVICE_ID, ALLOW );
		printf("var int d.%d.deny %d\n",   DEVICE_ID, DENY );
UPDATE = 0; READ = 0; CREATE=0; ALL=0; DENY=0; ALLOW=0;
}

end

atom type SmartContract ()

 data int VALUE
 data int BLOCK

 data int DENY
 data int ALLOW

 port Port_t p0()
 port Port_t p1()

 export port Port_ordererVALUE ordererVALUE( VALUE  )

 export port Port_ordererBlock ordererBlock( BLOCK  )

 place START, VALIDATION

 
 initial to START do { DENY=0; ALLOW=0;}

 on ordererVALUE from START to VALIDATION do { 

	if (VALUE==0  ) then ALLOW=0; DENY=1; BLOCK = readBlock();fi  
	if (VALUE>0  )   then ALLOW=1; DENY=0;  fi  


	}

 on ordererBlock from VALIDATION to START provided (ALLOW==1) do {  

		printf("var int SMARTCONTRACT IS ALLOWING VALUE %d \n",VALUE );
		printf("var int S.allow %d\n",  ALLOW );
		printf("var int S.deny %d\n",  DENY );

DENY=0; ALLOW=0;}

 on p0 from VALIDATION to START provided (DENY==1) do {  
		printf("var int SMARTCONTRACT IS DENYING VALUE %d \n",VALUE );
		printf("var int S.allow %d\n",  ALLOW );
		printf("var int S.deny %d\n",  DENY );

DENY=0; ALLOW=0;}

end

compound type Compound()
    component Device device( 0 )
    component Acl acl(  )
    component SmartContract smart ( )

    connector   connupdateValue  updatevalue (device.updateValue,  acl.updateValue)

    connector   connordererVALUE  orderervalue (acl.ordererVALUE,  smart.ordererVALUE)




  end


end