(base) ubuntu220402@ubuntu220402:~/Workspace/PDTE_rust_demo_4_middle_ciphertree$ cargo run --release
    Finished release [optimized] target(s) in 0.10s
warning: the following packages contain code that will be rejected by a future version of Rust: fs_extra v1.2.0
note: to see what the problems were, use the option `--future-incompat-report`, or run `cargo report future-incompatibilities --id 1`
     Running `target/release/homdte`
******************************* step 1: server begin *******************************
服务器读取决策树数据时间: 4.753963ms
服务器打印决策树，测试是否正确读取
Internal: feature: 7 threshold: 521 index: 0 op: LEQ
        left:Internal: feature: 20 threshold: 610 index: 0 op: LEQ
                left:Internal: feature: 13 threshold: 160 index: 0 op: LEQ
                        left:Internal: feature: 24 threshold: 1439 index: 0 op: LEQ
                                left:Internal: feature: 14 threshold: 111 index: 0 op: LEQ
                                        left:Internal: feature: 21 threshold: 858 index: 0 op: LEQ
                                                left:  Leaf: 0
                                                right:  Leaf: 1
                                        right:Internal: feature: 21 threshold: 1163 index: 0 op: LEQ
                                                left:  Leaf: 0
                                                right:Internal: feature: 21 threshold: 1175 index: 0 op: LEQ
                                                        left:  Leaf: 1
                                                        right:  Leaf: 0
                                right:  Leaf: 1
                        right:Internal: feature: 16 threshold: 103 index: 0 op: LEQ
                                left:  Leaf: 1
                                right:  Leaf: 0
                right:Internal: feature: 1 threshold: 449 index: 0 op: LEQ
                        left:  Leaf: 0
                        right:Internal: feature: 17 threshold: 393 index: 0 op: LEQ
                                left:  Leaf: 1
                                right:  Leaf: 0
        right:Internal: feature: 22 threshold: 624 index: 0 op: LEQ
                left:Internal: feature: 21 threshold: 744 index: 0 op: LEQ
                        left:Internal: feature: 27 threshold: 1175 index: 0 op: LEQ
                                left:  Leaf: 0
                                right:  Leaf: 1
                        right:Internal: feature: 12 threshold: 77 index: 0 op: LEQ
                                left:Internal: feature: 12 threshold: 64 index: 0 op: LEQ
                                        left:  Leaf: 1
                                        right:  Leaf: 0
                                right:  Leaf: 1
                right:  Leaf: 1
服务器生成默认参数..
WARNING: You are currently using the software variant of concrete-csprng which does not have access to a hardware source of randomness. To ensure the security of your application, please arrange to provide a secret by using the `concrete_csprng::set_soft_rdseed_secret` function.
WARNING: You are currently using the software variant of concrete-csprng which does not have access to a hardware source of randomness. To ensure the security of your application, please arrange to provide a secret by using the `concrete_csprng::set_soft_rdseed_secret` function.
WARNING: You are currently using the software variant of concrete-csprng which does not have access to a hardware source of randomness. To ensure the security of your application, please arrange to provide a secret by using the `concrete_csprng::set_soft_rdseed_secret` function.
WARNING: You are currently using the software variant of concrete-csprng which does not have access to a hardware source of randomness. To ensure the security of your application, please arrange to provide a secret by using the `concrete_csprng::set_soft_rdseed_secret` function.
服务器生成默认参数sk, RGSW(-s), ksk_map的时间: 2.213840108s
服务器对决策树进行加密并打印加密决策树部分数据
t= 858
t= 1175
t= 1163
t= 111
t= 1439
t= 103
t= 160
t= 393
t= 449
t= 610
t= 1175
t= 64
t= 77
t= 744
t= 624
t= 521
Internal: index: 0 op: LEQ
        left:Internal: index: 0 op: LEQ
                left:Internal: index: 0 op: LEQ
                        left:Internal: index: 0 op: LEQ
                                left:Internal: index: 0 op: LEQ
                                        left:Internal: index: 0 op: LEQ
                                                left:  Leaf: 0
                                                right:  Leaf: 1
                                        right:Internal: index: 0 op: LEQ
                                                left:  Leaf: 0
                                                right:Internal: index: 0 op: LEQ
                                                        left:  Leaf: 1
                                                        right:  Leaf: 0
                                right:  Leaf: 1
                        right:Internal: index: 0 op: LEQ
                                left:  Leaf: 1
                                right:  Leaf: 0
                right:Internal: index: 0 op: LEQ
                        left:  Leaf: 0
                        right:Internal: index: 0 op: LEQ
                                left:  Leaf: 1
                                right:  Leaf: 0
        right:Internal: index: 0 op: LEQ
                left:Internal: index: 0 op: LEQ
                        left:Internal: index: 0 op: LEQ
                                left:  Leaf: 0
                                right:  Leaf: 1
                        right:Internal: index: 0 op: LEQ
                                left:Internal: index: 0 op: LEQ
                                        left:  Leaf: 1
                                        right:  Leaf: 0
                                right:  Leaf: 1
                right:  Leaf: 1
服务器对决策树进行加密并打印加密决策树部分数据的时间为: 51.968647403s
******************************* step 1: server end *******************************
******************************* step 2: client begin *******************************
客户端生成默认参数
WARNING: You are currently using the software variant of concrete-csprng which does not have access to a hardware source of randomness. To ensure the security of your application, please arrange to provide a secret by using the `concrete_csprng::set_soft_rdseed_secret` function.
WARNING: You are currently using the software variant of concrete-csprng which does not have access to a hardware source of randomness. To ensure the security of your application, please arrange to provide a secret by using the `concrete_csprng::set_soft_rdseed_secret` function.
WARNING: You are currently using the software variant of concrete-csprng which does not have access to a hardware source of randomness. To ensure the security of your application, please arrange to provide a secret by using the `concrete_csprng::set_soft_rdseed_secret` function.
WARNING: You are currently using the software variant of concrete-csprng which does not have access to a hardware source of randomness. To ensure the security of your application, please arrange to provide a secret by using the `concrete_csprng::set_soft_rdseed_secret` function.
客户端生成默认参数时间: 393.215µs
客户端读取隐私数据
客户端打印文件，测试是否正确读取
Print x_test[0]: [1128, 803, 1102, 842, 692, 585, 518, 809, 540, 200, 502, 198, 456, 341, 190, 219, 117, 531, 229, 57, 1211, 794, 1159, 834, 651, 410, 439, 1258, 398, 146]
Print x_test[1]: [779, 677, 783, 508, 1045, 721, 703, 823, 900, 345, 269, 193, 225, 159, 315, 193, 145, 424, 233, 111, 792, 762, 733, 473, 1128, 421, 620, 1065, 514, 338]
Print x_test[2]: [472, 552, 488, 261, 975, 786, 371, 285, 776, 908, 48, 497, 140, 33, 577, 472, 251, 453, 535, 362, 315, 594, 365, 148, 998, 468, 393, 518, 400, 518]
Print x_test[3]: [386, 328, 389, 204, 872, 649, 323, 264, 784, 770, 123, 637, 84, 54, 726, 597, 287, 579, 402, 327, 268, 418, 253, 119, 856, 367, 294, 487, 309, 353]
Print x_test[4]: [1294, 1358, 1342, 961, 1204, 1806, 1685, 1546, 1382, 871, 455, 559, 484, 304, 335, 912, 368, 645, 587, 374, 1277, 1495, 1354, 811, 1268, 1670, 1535, 1864, 1018, 926]
Print x_test[5]: [1435, 844, 1445, 1152, 991, 1234, 1174, 1527, 790, 493, 664, 154, 656, 472, 158, 399, 185, 570, 279, 205, 1420, 752, 1462, 1017, 787, 718, 778, 1711, 475, 412]
Print x_test[6]: [990, 370, 977, 689, 847, 675, 474, 809, 702, 497, 362, 209, 376, 208, 273, 431, 176, 525, 434, 202, 848, 409, 837, 509, 734, 504, 407, 1024, 481, 324]
Print x_test[7]: [566, 426, 561, 307, 1019, 940, 561, 711, 912, 822, 129, 297, 75, 24, 354, 515, 206, 536, 514, 263, 513, 609, 439, 198, 1114, 897, 794, 1201, 792, 625]
Print x_test[8]: [622, 479, 598, 376, 289, 237, 107, 136, 778, 233, 32, 98, 61, 28, 111, 167, 51, 187, 202, 85, 484, 533, 486, 251, 307, 344, 226, 438, 450, 295]
Print x_test[9]: [553, 1076, 527, 322, 652, 229, 133, 210, 578, 253, 71, 448, 54, 41, 282, 89, 78, 250, 214, 66, 425, 1212, 383, 207, 780, 157, 227, 422, 355, 172]
Print x_test[10]: [911, 629, 894, 628, 665, 508, 404, 669, 861, 232, 361, 466, 325, 231, 307, 345, 136, 622, 498, 184, 851, 779, 793, 526, 617, 367, 379, 1037, 503, 231]
Print x_test[11]: [730, 696, 693, 456, 583, 239, 93, 197, 470, 116, 53, 319, 51, 38, 134, 88, 43, 249, 434, 44, 546, 753, 498, 283, 451, 145, 127, 405, 437, 78]
Print x_test[12]: [859, 843, 867, 576, 1180, 763, 863, 812, 836, 662, 340, 496, 213, 195, 616, 542, 302, 460, 1236, 375, 677, 719, 616, 381, 966, 366, 547, 736, 473, 329]
Print x_test[13]: [466, 177, 451, 261, 691, 306, 142, 269, 650, 350, 3, 61, 1, 8, 137, 106, 45, 223, 130, 34, 369, 395, 341, 173, 784, 358, 293, 753, 624, 280]
Print x_test[14]: [1144, 1148, 1182, 844, 1272, 1119, 929, 1495, 593, 960, 302, 1153, 487, 231, 406, 895, 110, 715, 867, 672, 872, 1129, 903, 545, 920, 505, 398, 1295, 302, 497]
Print x_test[15]: [714, 346, 680, 448, 593, 216, 164, 259, 619, 152, 79, 119, 89, 53, 348, 149, 77, 409, 303, 63, 519, 303, 491, 272, 578, 147, 180, 560, 311, 86]
Print x_test[16]: [248, 684, 245, 124, 881, 390, 24, 114, 756, 575, 98, 783, 86, 38, 779, 307, 22, 275, 682, 98, 148, 592, 139, 62, 748, 184, 16, 157, 282, 166]
Print x_test[17]: [0, 258, 0, 0, 1189, 395, 0, 0, 899, 1217, 83, 519, 77, 12, 590, 132, 0, 0, 715, 227, 0, 410, 0, 0, 1179, 185, 0, 0, 552, 521]
Print x_test[18]: [1289, 772, 1309, 999, 960, 1083, 1000, 1345, 1103, 541, 435, 285, 381, 310, 200, 367, 207, 551, 443, 127, 1169, 734, 1100, 805, 752, 569, 725, 1511, 611, 277]
Print x_test[19]: [612, 421, 619, 363, 888, 761, 374, 516, 622, 677, 124, 118, 116, 63, 209, 282, 91, 357, 165, 158, 591, 482, 581, 299, 945, 649, 454, 973, 414, 644]
Print x_test[20]: [442, 555, 439, 242, 929, 548, 229, 338, 907, 502, 128, 584, 107, 59, 448, 216, 95, 291, 469, 64, 365, 752, 352, 170, 974, 298, 262, 441, 599, 212]
Print x_test[21]: [1395, 870, 1405, 1086, 1184, 1327, 1348, 1589, 1139, 694, 380, 254, 328, 284, 244, 538, 244, 499, 480, 222, 1313, 912, 1223, 943, 1068, 1081, 1153, 1704, 914, 613]
Print x_test[22]: [235, 801, 222, 120, 527, 138, 12, 52, 589, 622, 54, 444, 41, 18, 279, 53, 11, 137, 251, 108, 182, 923, 161, 77, 560, 87, 20, 181, 317, 343]
Print x_test[23]: [392, 1023, 383, 216, 408, 263, 95, 134, 904, 380, 103, 645, 116, 44, 307, 324, 83, 271, 919, 93, 282, 1069, 280, 128, 328, 216, 118, 339, 678, 167]
Print x_test[24]: [585, 85, 582, 341, 1413, 598, 330, 667, 1388, 709, 221, 296, 183, 99, 813, 401, 60, 319, 682, 373, 404, 25, 384, 194, 999, 220, 140, 521, 463, 226]
Print x_test[25]: [560, 278, 551, 326, 572, 465, 244, 291, 576, 258, 53, 77, 81, 32, 178, 284, 146, 328, 257, 122, 416, 292, 438, 203, 614, 479, 469, 645, 473, 244]
Print x_test[26]: [261, 1239, 258, 132, 696, 401, 288, 279, 551, 488, 80, 850, 66, 29, 720, 386, 248, 667, 403, 286, 162, 1249, 157, 68, 909, 286, 327, 642, 267, 373]
Print x_test[27]: [508, 632, 494, 286, 815, 421, 129, 181, 723, 512, 81, 418, 75, 40, 271, 218, 79, 388, 428, 88, 380, 762, 347, 180, 793, 311, 205, 585, 476, 233]
Print x_test[28]: [953, 1025, 965, 666, 1006, 1147, 812, 808, 896, 643, 355, 308, 284, 240, 286, 828, 220, 437, 282, 382, 1096, 1189, 1011, 740, 1181, 1414, 1074, 1336, 706, 1059]
Print x_test[29]: [345, 881, 343, 182, 795, 438, 231, 230, 1003, 671, 125, 501, 119, 42, 124, 434, 178, 397, 812, 271, 250, 886, 243, 108, 507, 300, 256, 451, 648, 339]
Print x_test[30]: [438, 210, 421, 244, 748, 231, 95, 200, 548, 393, 52, 167, 40, 25, 266, 115, 43, 243, 259, 116, 334, 348, 308, 157, 762, 191, 141, 494, 383, 321]
Print x_test[31]: [206, 652, 204, 104, 1014, 448, 43, 200, 1528, 876, 433, 627, 371, 140, 790, 255, 31, 408, 883, 236, 190, 608, 180, 79, 928, 215, 34, 323, 659, 336]
Print x_test[32]: [600, 458, 580, 355, 741, 373, 84, 191, 590, 500, 69, 54, 59, 40, 147, 76, 37, 197, 102, 57, 537, 446, 490, 279, 747, 257, 197, 612, 501, 306]
Print x_test[33]: [250, 542, 250, 125, 988, 460, 85, 195, 879, 824, 100, 388, 85, 32, 431, 180, 44, 296, 706, 203, 187, 590, 182, 77, 939, 232, 107, 392, 602, 442]
Print x_test[34]: [384, 626, 370, 209, 787, 248, 146, 232, 889, 393, 158, 271, 138, 64, 461, 99, 70, 336, 928, 106, 312, 570, 284, 143, 726, 119, 148, 444, 703, 206]
Print x_test[35]: [835, 937, 797, 551, 543, 331, 158, 338, 484, 302, 198, 374, 165, 129, 161, 108, 57, 294, 257, 152, 787, 1192, 721, 470, 634, 254, 239, 702, 559, 396]
Print x_test[36]: [406, 299, 383, 225, 471, 168, 108, 281, 1076, 481, 334, 411, 286, 119, 440, 187, 78, 716, 815, 79, 347, 340, 314, 157, 438, 115, 110, 583, 620, 159]
Print x_test[37]: [1059, 711, 1044, 763, 776, 628, 541, 753, 759, 322, 248, 187, 234, 180, 181, 177, 117, 403, 222, 91, 1063, 853, 1027, 702, 987, 458, 619, 1359, 605, 385]
Print x_test[38]: [695, 991, 679, 432, 685, 467, 149, 301, 646, 375, 193, 340, 147, 103, 220, 244, 58, 334, 496, 142, 556, 932, 504, 294, 545, 297, 150, 489, 387, 234]
Print x_test[39]: [281, 663, 284, 145, 873, 465, 144, 122, 1196, 640, 180, 531, 149, 62, 410, 306, 149, 334, 734, 181, 214, 616, 205, 91, 686, 241, 131, 225, 509, 275]
Print x_test[40]: [741, 1110, 729, 479, 919, 549, 592, 667, 607, 633, 401, 518, 330, 216, 613, 339, 254, 677, 509, 281, 736, 1156, 694, 419, 1282, 414, 659, 1073, 440, 528]
Print x_test[41]: [393, 437, 401, 209, 1038, 683, 340, 458, 854, 571, 99, 169, 88, 35, 290, 273, 136, 506, 405, 77, 297, 417, 286, 128, 951, 377, 376, 777, 494, 258]
Print x_test[42]: [416, 639, 402, 226, 666, 348, 128, 142, 489, 457, 82, 228, 66, 39, 265, 231, 106, 262, 316, 144, 346, 707, 320, 163, 768, 319, 241, 486, 392, 334]
Print x_test[43]: [421, 530, 412, 233, 1291, 369, 284, 753, 987, 379, 392, 874, 315, 161, 868, 194, 65, 741, 722, 149, 279, 380, 260, 126, 875, 112, 117, 629, 265, 71]
Print x_test[44]: [366, 800, 357, 198, 646, 325, 246, 193, 441, 661, 91, 283, 81, 37, 515, 204, 126, 250, 298, 112, 324, 934, 307, 149, 1335, 382, 510, 582, 511, 447]
Print x_test[45]: [161, 290, 175, 76, 1561, 723, 160, 246, 1175, 1164, 179, 348, 157, 49, 957, 355, 114, 613, 1226, 213, 142, 317, 139, 52, 1539, 362, 163, 511, 854, 467]
Print x_test[46]: [174, 1258, 165, 88, 528, 212, 0, 0, 705, 458, 315, 1161, 276, 85, 687, 138, 0, 0, 847, 172, 136, 1212, 125, 54, 488, 88, 0, 0, 368, 197]
Print x_test[47]: [399, 714, 397, 216, 905, 527, 201, 219, 826, 632, 70, 233, 61, 33, 246, 231, 95, 205, 253, 126, 350, 916, 338, 166, 1133, 535, 451, 571, 663, 463]
Print x_test[48]: [521, 415, 526, 304, 472, 536, 535, 345, 384, 405, 133, 465, 153, 63, 328, 574, 410, 688, 417, 198, 391, 418, 392, 188, 380, 406, 547, 715, 176, 218]
Print x_test[49]: [952, 856, 927, 665, 824, 495, 435, 664, 834, 252, 229, 171, 199, 148, 194, 150, 106, 383, 136, 48, 965, 944, 895, 615, 1144, 456, 636, 1396, 667, 277]
Print x_test[50]: [1097, 1066, 1119, 806, 993, 1187, 1112, 1266, 1161, 518, 533, 500, 465, 375, 316, 484, 269, 449, 466, 259, 1083, 1200, 1103, 734, 1054, 791, 1003, 1300, 759, 574]
Print x_test[51]: [543, 888, 569, 315, 879, 904, 418, 519, 817, 998, 60, 254, 71, 32, 246, 433, 131, 322, 659, 234, 440, 935, 468, 211, 862, 820, 517, 792, 1035, 706]
Print x_test[52]: [626, 240, 617, 372, 1333, 548, 484, 673, 947, 630, 322, 1029, 322, 145, 580, 464, 246, 1106, 354, 328, 445, 183, 417, 218, 922, 217, 255, 714, 241, 235]
Print x_test[53]: [422, 342, 439, 230, 1156, 772, 178, 306, 967, 1226, 211, 133, 218, 70, 589, 694, 144, 430, 894, 603, 335, 245, 331, 145, 963, 446, 154, 425, 469, 652]
Print x_test[54]: [549, 589, 529, 322, 407, 284, 233, 292, 407, 238, 67, 147, 46, 39, 296, 195, 81, 328, 117, 55, 466, 647, 423, 235, 771, 336, 307, 735, 271, 191]
Print x_test[55]: [257, 448, 271, 135, 988, 643, 323, 403, 706, 984, 190, 502, 81, 61, 611, 621, 207, 599, 738, 474, 195, 468, 177, 84, 933, 415, 310, 685, 421, 564]
Print x_test[56]: [1757, 1052, 1799, 1499, 991, 1732, 1601, 1877, 795, 770, 582, 504, 639, 433, 449, 840, 296, 787, 106, 354, 1595, 1178, 1636, 1187, 1164, 1153, 1059, 2017, 319, 672]
Print x_test[57]: [580, 769, 589, 341, 905, 744, 510, 553, 682, 613, 75, 105, 76, 45, 254, 309, 158, 489, 225, 162, 513, 764, 550, 262, 1214, 785, 822, 1588, 502, 699]
Print x_test[58]: [361, 231, 354, 191, 844, 397, 157, 280, 733, 549, 58, 76, 39, 24, 331, 137, 66, 343, 345, 136, 273, 227, 247, 118, 874, 245, 208, 616, 472, 338]
Print x_test[59]: [518, 574, 513, 295, 863, 533, 187, 236, 680, 431, 114, 332, 98, 52, 249, 220, 107, 317, 367, 138, 416, 698, 389, 202, 780, 371, 283, 558, 490, 324]
Print x_test[60]: [1203, 799, 1195, 907, 1052, 985, 947, 1301, 1043, 432, 470, 193, 369, 334, 309, 581, 198, 798, 559, 260, 1114, 737, 1020, 754, 990, 789, 736, 1709, 827, 437]
Print x_test[61]: [1390, 878, 1370, 1149, 1078, 676, 1170, 1413, 688, 270, 789, 405, 667, 581, 598, 409, 269, 952, 125, 237, 1255, 784, 1161, 915, 944, 366, 671, 1559, 200, 216]
Print x_test[62]: [673, 1196, 645, 417, 320, 230, 167, 177, 669, 188, 89, 249, 94, 52, 254, 223, 102, 247, 239, 71, 503, 1089, 478, 259, 413, 236, 241, 391, 315, 129]
Print x_test[63]: [462, 645, 436, 258, 563, 159, 37, 87, 495, 409, 53, 530, 43, 25, 429, 95, 36, 253, 440, 94, 350, 897, 313, 162, 690, 126, 59, 280, 400, 229]
Print x_test[64]: [494, 987, 487, 286, 487, 392, 261, 207, 469, 441, 99, 319, 66, 45, 241, 318, 156, 337, 221, 178, 413, 1052, 377, 203, 697, 632, 639, 830, 509, 548]
Print x_test[65]: [811, 914, 841, 537, 1161, 1092, 1023, 964, 1071, 1007, 326, 322, 274, 198, 486, 576, 308, 539, 270, 360, 861, 1008, 789, 532, 1546, 924, 1203, 1431, 690, 942]
Print x_test[66]: [1252, 987, 1394, 944, 1403, 2047, 1800, 1632, 1908, 1356, 608, 690, 761, 419, 603, 1016, 564, 1005, 2047, 360, 1099, 1075, 1205, 710, 1254, 1170, 1256, 1764, 1564, 599]
Print x_test[67]: [413, 532, 398, 227, 888, 254, 113, 158, 680, 338, 55, 708, 25, 29, 426, 100, 80, 242, 898, 78, 291, 789, 261, 135, 871, 145, 144, 303, 660, 144]
Print x_test[68]: [530, 668, 533, 301, 797, 653, 341, 300, 725, 666, 116, 93, 165, 53, 280, 465, 227, 380, 750, 260, 430, 542, 465, 208, 779, 592, 562, 693, 820, 492]
Print x_test[69]: [609, 871, 622, 367, 1245, 752, 664, 664, 800, 811, 376, 792, 400, 164, 841, 480, 241, 799, 726, 242, 577, 1200, 594, 296, 1386, 566, 623, 1177, 612, 514]
Print x_test[70]: [811, 566, 811, 536, 821, 770, 477, 672, 808, 468, 292, 283, 271, 181, 283, 589, 144, 497, 466, 230, 879, 832, 853, 546, 925, 1060, 648, 1273, 899, 668]
Print x_test[71]: [639, 517, 609, 385, 514, 240, 129, 331, 601, 331, 28, 599, 46, 22, 255, 161, 59, 355, 356, 39, 467, 726, 436, 234, 479, 190, 138, 556, 387, 148]
Print x_test[72]: [879, 720, 894, 582, 844, 955, 860, 902, 759, 572, 142, 418, 166, 95, 342, 594, 278, 703, 342, 261, 682, 896, 718, 384, 951, 873, 958, 1431, 601, 539]
Print x_test[73]: [4, 1093, 1, 7, 523, 206, 0, 0, 837, 987, 197, 498, 167, 47, 762, 114, 0, 0, 800, 423, 30, 1031, 28, 12, 736, 112, 0, 0, 603, 595]
Print x_test[74]: [579, 301, 573, 330, 1006, 674, 278, 536, 743, 708, 35, 96, 33, 23, 191, 188, 69, 341, 348, 134, 460, 343, 421, 221, 921, 442, 302, 939, 671, 513]
Print x_test[75]: [636, 799, 609, 380, 703, 351, 70, 193, 472, 362, 109, 517, 88, 58, 395, 178, 38, 389, 182, 144, 498, 996, 456, 249, 778, 246, 102, 560, 267, 284]
Print x_test[76]: [628, 508, 633, 379, 1052, 761, 469, 534, 877, 489, 232, 203, 174, 111, 323, 377, 161, 520, 487, 128, 577, 548, 558, 306, 1082, 594, 525, 967, 607, 329]
Print x_test[77]: [307, 364, 296, 162, 467, 224, 108, 80, 350, 298, 104, 398, 101, 42, 337, 239, 104, 218, 337, 104, 245, 474, 242, 110, 493, 189, 159, 240, 297, 170]
Print x_test[78]: [359, 225, 367, 189, 1313, 643, 379, 565, 990, 827, 107, 283, 101, 35, 343, 238, 109, 451, 504, 200, 312, 464, 317, 128, 1214, 428, 367, 927, 718, 498]
Print x_test[79]: [849, 819, 848, 561, 890, 764, 500, 571, 1137, 386, 238, 409, 201, 141, 220, 265, 115, 358, 285, 105, 808, 1072, 783, 483, 924, 553, 489, 923, 773, 284]
Print x_test[80]: [357, 351, 341, 193, 562, 176, 5, 30, 737, 468, 76, 288, 74, 32, 272, 75, 5, 114, 349, 81, 306, 548, 287, 136, 614, 141, 9, 117, 505, 257]
Print x_test[81]: [681, 814, 674, 419, 772, 561, 577, 502, 1049, 276, 229, 841, 245, 123, 533, 424, 278, 683, 623, 167, 564, 940, 561, 297, 803, 338, 548, 862, 588, 180]
Print x_test[82]: [1328, 959, 1325, 1048, 888, 990, 1301, 1333, 1184, 389, 661, 208, 542, 501, 249, 566, 492, 723, 616, 291, 1265, 817, 1153, 907, 675, 576, 1143, 1481, 630, 315]
Print x_test[83]: [1026, 1023, 979, 727, 663, 357, 273, 483, 494, 222, 229, 485, 194, 149, 260, 145, 84, 330, 241, 132, 916, 1237, 839, 556, 816, 305, 340, 799, 379, 328]
Print x_test[84]: [765, 524, 805, 477, 1494, 1465, 1174, 1264, 1383, 1121, 406, 316, 319, 201, 587, 670, 258, 825, 419, 549, 677, 580, 680, 358, 1424, 840, 724, 1568, 684, 860]
客户端读取隐私数据时间: 1.393427ms
客户端进行隐私决策树评估..
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
进入到server_f中
客户端评估 30 行数据, 完成 step 2 的时间为 27.537059236s 
客户端向服务器发送比较结果的密文
*******************************ste 2: client end*******************************
*******************************step 3: server begin *******************************
服务器接收到比较结果的密文
服务器解密并进行验证
actual_scalar:1
expected_scalar:1
actual_scalar:1
expected_scalar:1
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:1
expected_scalar:1
actual_scalar:1
expected_scalar:1
actual_scalar:1
expected_scalar:1
actual_scalar:1
expected_scalar:1
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:1
expected_scalar:1
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:1
expected_scalar:1
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:1
expected_scalar:1
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:1
expected_scalar:1
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:0
expected_scalar:0
actual_scalar:1
expected_scalar:1
actual_scalar:0
expected_scalar:0
服务器解密并进行验证的时间为 403.230741ms 

总时间为: 79.916515752s