/*
 * Test Harness for ESG Security extensions to NetCDF OPeNDAP client
 *
 * Author: Steve Crothers
 *
 * Modified: Philip Kershaw
 *
 * Copyright: STFC Rutherford Appleton Laboratory
 *
 * $Id$
 */
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h>

#include "netcdf.h"


int main(int argc, char **argv) 
{
    int ncId, status;
    int nDims, nVars, nGlobalAttrs, unlimitedDimId;
    
    int i=0;
    int j=0;
    nc_type varType;
    char varName[NC_MAX_NAME+1];
    int varNDims;
    int varDimIds[NC_MAX_VAR_DIMS];
    int varNVarAttrs;
    
    printf("%s\n",nc_inq_libvers());
    
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s <netcdf file>\n", 
                (const char *)basename(argv[0]));
        exit(1);
    }
    printf("Go %s\n", argv[1]);
    status = nc_open(argv[1], NC_NOWRITE, &ncId);
    printf("Got nc_open status=%d; id=%d\n", status, ncId);
    if (status != NC_NOERR) 
    {
        fprintf(stderr, "Opening URI: %s\n", nc_strerror(status));
        exit(1);
    }

    status = nc_inq(ncId, &nDims, &nVars, &nGlobalAttrs, &unlimitedDimId);
    if (status != NC_NOERR) 
    {
        printf("Getting information about dataset: %s\n", nc_strerror(status));
        exit(1);
    }
    
    printf("Number of dimensions: %d\n", nDims);
    printf("Number of variables: %d\n", nVars);
    printf("Number of global attributes: %d\n", nGlobalAttrs);
    printf("Unlimited dimension ID: %d\n", unlimitedDimId);

    for (i=0; i < nVars; i++)
    {
        status = nc_inq_var(ncId, i, &varName, &varType,
                            &varNDims, varDimIds, &varNVarAttrs);
        if (status != NC_NOERR)
        {
            printf("Getting information about variable %d: %s\n", i,
                   nc_strerror(status));
            exit(1);
        }
        printf("Variable name: %s\n", varName);
        printf("Variable type: %d\n", varType);
        for (j=0; j < varNDims; j++)
            printf("Variable dimension ID: %d\n", varDimIds[j]);
            
        printf("Variable number of variable attributes: %d\n", varNVarAttrs);
    }
    
    nc_close(ncId);
    
    exit(0);
}

