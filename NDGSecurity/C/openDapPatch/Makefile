
NETCDF_LIB=-lnetcdf
NETCDF_ROOT_PATH=../netcdf-4.1.2-beta2
NETCDF_LIB_PATH=-L${NETCDF_ROOT_PATH}/liblib/.libs
NETCDF_INCLUDES=-I${NETCDF_ROOT_PATH}/include

ncopen: ncopen.c
	cc -Wall -g ${NETCDF_INCLUDES} ${NETCDF_LIB_PATH} ncopen.c ${NETCDF_LIB} -lcurl -o ncopen 
	
clean:
	-rm -f ncopen
