from idautils import *
from idaapi import *
from idc import *
 
def decompile_func(ea):
    print ea
    if not init_hexrays_plugin():
        return False
 
    f = get_func(ea)
    if f is None:
        return False
 
    try:
        cfunc = decompile(f);
        if cfunc is None:
        # Failed to decompile
            print "fase"
            return False
    except Exception as e:
        print e
        return 'DecompileFail'
        
    lines = []
    sv = cfunc.get_pseudocode();
    for sline in sv:
        line = tag_remove(sline.line);
        lines.append(line)
    return "\n".join(lines)
 
filename = GetInputFile().split(".")[0]

print filename
for segea in Segments():
    for funcea in Functions(segea, SegEnd(segea)):
        functionName = GetFunctionName(funcea)
        decompile_func(funcea)
        for (startea, endea) in Chunks(funcea):
            index = index + 1
            print startea, endea
            decompiled_result = decompile_func(startea)
            if decompiled_result == False:
                pass
 
            elif decompiled_result == 'DecompileFail':
                pass
                #with open('decompileError_{0}'.format(filename), 'a') as error: error.write(str(hex(startea))+'\n')
            else:
                output_file_name = '{0}/{1}.log'.format(filename, functionName).replace("?", "")
                with open(output_file_name, 'a') as ohoh: ohoh.write(str(decompiled_result))
 
