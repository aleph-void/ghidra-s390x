# Mnemonic sets shared by the test tools (the HFP instructions model_diff.py checks).
HFP_NAMES = set("""ad adr ae aer au aur aw awr axr cd cdfr cdgr cdr ce cefr cegr cer cfdr cfer cfxr cgdr cger
cgxr cxfr cxgr cxr dd ddr de der dxr fidr fier fixr hdr her lcdr lcer lcxr lde lder ldxr ledr lexr
lndr lner lnxr lpdr lper lpxr lrdr lrer ltdr lter ltxr lxd lxdr lxe lxer mad madr mae maer md mde
mder mdr me mee meer mer msd msdr mse mser mxd mxdr mxr sd sdr se ser sqd sqdr sqe sqer sqxr su sur
sw swr sxr tbdr tbedr thdr thder may mayr mayh mayhr mayl maylr my myr myh myhr myl mylr""".split())

# Decimal floating point (model_diff.py dfp, test/dfp_model.py).
DFP_NAMES = set("""adtr adtra axtr axtra sdtr sdtra sxtr sxtra mdtr mdtra mxtr mxtra ddtr ddtra dxtr dxtra
cdtr cxtr kdtr kxtr cedtr cextr cdgtr cdgtra cxgtr cxgtra cdftr cxftr cdlgtr cxlgtr cdlftr cxlftr cgdtr
cgdtra cgxtr cgxtra cfdtr cfxtr clgdtr clgxtr clfdtr clfxtr cdstr cxstr cdutr cxutr csdtr csxtr cudtr cuxtr
cdpt cxpt cpdt cpxt cdzt cxzt czdt czxt eedtr eextr esdtr esxtr iedtr iextr fidtr fixtr ldetr lxdtr ledtr
ldxtr qadtr qaxtr rrdtr rrxtr sldt slxt srdt srxt tdcet tdcdt tdcxt tdget tdgdt tdgxt ltdtr ltxtr""".split())

# Vector packed decimal (model_diff.py vpd).
VPD_NAMES = set("""vap vsp vmp vmsp vdp vrp vsdp vsrp vsrpr vcp vcvd vcvdg vcvdq vcvb vcvbg vcvbq vlip vpkz
vupkz vupkzh vupkzl vpkzr vclzdp vpsop vtp vtz vschp vschsp vschdp vschxp vscshp vcsph""".split())
