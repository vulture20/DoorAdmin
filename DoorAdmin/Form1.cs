using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Drawing.Text;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using PCSC;
using PCSC.Iso7816;
using Be.Windows.Forms;

namespace DoorAdmin
{
    public partial class Form1 : Form
    {
        String swVersion = "v0.3";

        String readerName;
        SCardMonitor monitor;
        private PrivateFontCollection fonts = new PrivateFontCollection();
        private DynamicByteProvider cardByteProvider;
        enum cardtype
        {
            Unknown, Mifare1K, Mifare4K, MifareUL, MifareMi, ToapzJwl, FeliCa212, FeliCa424, DESFire
        };
        cardtype cardType = cardtype.Unknown;

        byte[] Mifare1K = { 0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x6A };
        byte[] Mifare4K = { 0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x6A };
        byte[] MifareUL = { 0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x6A };
        byte[] MifareMi = { 0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x6A };
        byte[] TopazJwl = { 0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0xF0, 0x04, 0x00, 0x00, 0x00, 0x00, 0x6A };
        byte[] FeliCa212 = { 0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0xF0, 0x11, 0x00, 0x00, 0x00, 0x00, 0x6A };
        byte[] FeliCa424 = { 0x3B, 0x8F, 0x80, 0x01, 0x80, 0x4F, 0x0C, 0xA0, 0x00, 0x00, 0x03, 0x06, 0x03, 0xF0, 0x12, 0x00, 0x00, 0x00, 0x00, 0x6A };
        byte[] DESFire = { 0x3B, 0x86, 0x80, 0x01, 0x06, 0x75, 0x77, 0x81, 0x02, 0x80, 0x00 };

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            String[] readerNames;

            using (var context = new SCardContext())
            {
                context.Establish(SCardScope.System);
                if (!context.IsValid())
                {
                    MessageBox.Show("PCSC konnte nicht initialisiert werden!");
                    Environment.Exit(2);
                }
                try
                {
                    readerNames = context.GetReaders();
                    if (readerNames == null || readerNames.Length == 0)
                    {
                        MessageBox.Show("Kein Kartenlesegerät gefunden!");
                        Environment.Exit(3);
                    }
                    readerName = readerNames[0];
                }
                catch (PCSCException ex)
                {
                    MessageBox.Show("Kein Kartenlesegerät gefunden! [" + ex.ToString() + "]");
                    Environment.Exit(4);
                }

                monitor = new SCardMonitor(new SCardContext(), SCardScope.System);
                monitor.CardInserted += new CardInsertedEvent(monitor_CardInserted);
                monitor.CardRemoved += new CardRemovedEvent(monitor_CardRemoved);
                monitor.Initialized += new CardInitializedEvent(monitor_Initialized);
                monitor.StatusChanged += StatusChanged;
                monitor.MonitorException += MonitorException;

                monitor.Start(readerName);

                context.Release();
            }
        }

        void monitor_CardInserted(object sender, CardStatusEventArgs e)
        {
            String temp;
            string[] readerNames;
            SCardProtocol proto;
            SCardState state;
            byte[] atr;

            cardType = detectATR(e.Atr);
            //toolStripStatusLabel1.Text = "Karte gefunden - ATR: " + BitConverter.ToString(e.Atr ?? new byte[0]) + (e.Atr.ToString().Contains(Mifare1K.ToString()) ? " (Mifare 1K)" : " (unknown Type)");
            toolStripStatusLabel1.Text = "Karte gefunden - ATR: " + BitConverter.ToString(e.Atr ?? new byte[0]) + " (" + Enum.GetName(typeof(cardtype), cardType) + ")";
            
            using (var context = new SCardContext())
            {
                context.Establish(SCardScope.System);
                using (var reader = new SCardReader(context))
                {
                    textBox1.AppendText("Trying to connect to Reader: " + readerName + "\n");
                    var sc = reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
                    if (sc == SCardError.Success)
                    {
                        var rs = reader.Status(out readerNames, out state, out proto, out atr);
                        if (rs == SCardError.Success)
                        {
                            temp = "Connected with protocol " + proto + " in state " + state + "\n";
                            textBox1.AppendText(temp);
                            temp = "Card ATR: " + BitConverter.ToString(atr) + "\n";
                            textBox1.AppendText(temp);
                        }
                        else
                        {
                            temp = "Unable to retrieve card status. \n Error message: " + SCardHelper.StringifyError(rs) + "\n";
                            textBox1.AppendText(temp);
                        }
                    }
                    else
                    {
                        textBox1.AppendText("No card inserted or reader is reserved exclusively by another application.\n");
                        temp = "Error message: " + SCardHelper.StringifyError(sc) + "\n";
                        textBox1.AppendText(temp);
                    }
                }
            }
        }

        void monitor_CardRemoved(object sender, CardStatusEventArgs e)
        {
            toolStripStatusLabel1.Text = "Karte entfernt";
        }

        void monitor_Initialized(object sender, CardStatusEventArgs e)
        {
/*            if (setBuzzer(false))
            {
                toolStripStatusLabel1.Text = "Buzzer deaktiviert";
            }
            else
            {
                toolStripStatusLabel1.Text = "Buzzer konnte nicht deaktiviert werden!";
            }*/
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            try
            {
                monitor.Cancel();
            }
            catch (Exception ex)
            {
                ex.ToString();
            }
        }

        private void StatusChanged(object sender, StatusChangeEventArgs args)
        {
            String temp;
            temp = "Last State: " + args.LastState + " - New State: " + args.NewState + "\n";
//            textBox1.AppendText(temp);
        }

        private void MonitorException(object sender, PCSCException ex)
        {
            String temp;
            temp = "MonitorException: " + SCardHelper.StringifyError(ex.SCardError);
            MessageBox.Show(temp);
        }

        ResponseApdu transferAPDU(byte CLA, InstructionCode Instruction, byte P1, byte P2, Int16 Le, byte[] Data)
        {
            CommandApdu apdu;

            using (var context = new SCardContext())
            {
                context.Establish(SCardScope.System);
                using (var rfidReader = new SCardReader(context))
                {
                    var sc = rfidReader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
                    if (sc != SCardError.Success) return null;
                    if (Data == null)
                    {
                        apdu = new CommandApdu(IsoCase.Case2Short, rfidReader.ActiveProtocol)
                        {
                            CLA = CLA,
                            Instruction = Instruction,
                            P1 = P1,
                            P2 = P2,
                            Le = Le
                        };
                    }
                    else
                    {
                        apdu = new CommandApdu(IsoCase.Case3Short, rfidReader.ActiveProtocol)
                        {
                            CLA = CLA,
                            Instruction = Instruction,
                            P1 = P1,
                            P2 = P2,
                            Data = Data
                        };
                    }
                    sc = rfidReader.BeginTransaction();
                    if (sc != SCardError.Success) return null;
                    var receivePci = new SCardPCI();
                    var sendPci = SCardPCI.GetPci(rfidReader.ActiveProtocol);
                    var receiveBuffer = new byte[256];
                    var command = apdu.ToArray();
                    sc = rfidReader.Transmit(sendPci, command, receivePci, ref receiveBuffer);
                    if (sc != SCardError.Success) return null;
                    var responseApdu = new ResponseApdu(receiveBuffer, IsoCase.Case2Short, rfidReader.ActiveProtocol);
                    rfidReader.EndTransaction(SCardReaderDisposition.Leave);
                    rfidReader.Disconnect(SCardReaderDisposition.Reset);
                    return responseApdu;
                }
            }
        }

        bool setBuzzer(bool state)
        {
            byte buzzStatus; String temp;

            buzzStatus = Convert.ToByte(state ? 0xFF : 0x00);

            using (var context = new SCardContext())
            {
                context.Establish(SCardScope.System);
                using (var rfidReader = new SCardReader(context))
                {
//                    var sc = rfidReader.Connect(readerName, SCardShareMode.Direct, SCardProtocol.Unset);
                    var sc = rfidReader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
                    if (sc != SCardError.Success) return false;
                    var apdu = new CommandApdu(IsoCase.Case2Short, rfidReader.ActiveProtocol)
                    {
                        CLA = 0xFF,
                        Instruction = 0x00,
                        P1 = 0x52,
                        P2 = buzzStatus,
                        Le = 0
                    };
                    sc = rfidReader.BeginTransaction();
                    if (sc != SCardError.Success) return false;
                    var receivePci = new SCardPCI();
                    var sendPci = SCardPCI.GetPci(rfidReader.ActiveProtocol);
//                    var sendPci = SCardPCI.GetPci(SCardProtocol.T1);
                    var receiveBuffer = new byte[256];
                    var command = apdu.ToArray();
//                    sc = rfidReader.Control(context.Handle, command, ref receiveBuffer);
                    sc = rfidReader.Transmit(
                        sendPci,
                        command,
                        receivePci,
                        ref receiveBuffer);
                    if (sc != SCardError.Success) return false;
                    var responseApdu = new ResponseApdu(receiveBuffer, IsoCase.Case2Short, rfidReader.ActiveProtocol);
                    rfidReader.EndTransaction(SCardReaderDisposition.Leave);
                    rfidReader.Disconnect(SCardReaderDisposition.Reset);

                    if (responseApdu.SW1 == 0x90)
                    {
                        if (responseApdu.SW2 == 0xFF)
                        {
                            aktiviertToolStripMenuItem.Checked = true;
                            deaktiviertToolStripMenuItem.Checked = false;
                        }
                        else if (responseApdu.SW2 == 0x00)
                        {
                            aktiviertToolStripMenuItem.Checked = false;
                            deaktiviertToolStripMenuItem.Checked = true;
                        }
                    }

                    temp = "SW1: " + responseApdu.SW1 + " - SW2: " + responseApdu.SW2 + " - StatusWord: " + responseApdu.StatusWord;
                    MessageBox.Show(temp);
                    if (responseApdu.SW1 == 0x90)
                    {
                        return true;
                    }
                    else
                    {
                        return false;
                    }
                }

            }
        }

        byte[] getUID()
        {
            String temp;
            byte[] uid;

            var responseApdu = transferAPDU(0xFF, InstructionCode.GetData, 0x00, 0x00, 0, null);
            temp = "SW1: " + responseApdu.SW1 + " - SW2: " + responseApdu.SW2 + " - StatusWord: " + responseApdu.StatusWord;
            MessageBox.Show(temp);
            if (responseApdu.SW1 == 0x90)
            {
                uid = responseApdu.GetData();
                return uid;
            }
            else
            {
                return null;
            }
        }

        bool loadKey(byte[] key, byte keyNr)
        {
            String temp;

            var responseApdu = transferAPDU(0xFF, InstructionCode.ExternalAuthenticate, 0x00, keyNr, 0x06, key);
            temp = "SW1: " + responseApdu.SW1 + " - SW2: " + responseApdu.SW2 + " - StatusWord: " + responseApdu.StatusWord;
            MessageBox.Show(temp);
            if (responseApdu.SW1 == 0x90)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        bool authenticate(byte blockNumber, byte keyType, byte keyNumber)
        {
            String temp;
            byte[] Data = { 0x01, 0x00, blockNumber, keyType, keyNumber };

            var responseApdu = transferAPDU(0xFF, InstructionCode.InternalAuthenticate, 0x00, 0x00, 0x05, Data);
            temp = "SW1: " + responseApdu.SW1 + " - SW2: " + responseApdu.SW2 + " - StatusWord: " + responseApdu.StatusWord;
//            MessageBox.Show(temp);
            if (responseApdu.SW1 == 0x90)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        byte[] readBinary(byte blockNumber, byte byteCount)
        {
            String temp;

            var responseApdu = transferAPDU(0xFF, InstructionCode.ReadBinary, 0x00, blockNumber, byteCount, null);
            temp = "SW1: " + responseApdu.SW1 + " - SW2: " + responseApdu.SW2 + " - StatusWord: " + responseApdu.StatusWord;
//            MessageBox.Show(temp);
            if (responseApdu.SW1 == 0x90)
            {
                return responseApdu.GetData();
            }
            else
            {
                return null;
            }
        }

        byte[] readCard()
        {
            byte[] key = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
            byte[] temp = null;
            byte x;

            var Data = new byte[1024];
            if (!loadKey(key, 0)) return null;
            for (x = 0; x < 64; x++)
            {
                if (x % 4 == 0)
                {
                    if (!authenticate(x, 0x60, 0)) return null;
                }
                temp = readBinary(x, 16);
                if (temp == null) return null;
                Buffer.BlockCopy(temp, 0, Data, (x * 16), 16);
            }
            return Data;
        }

        private void beendenToolStripMenuItem_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void aktiviertToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (setBuzzer(true))
            {
                toolStripStatusLabel1.Text = "Buzzer aktiviert";
            }
            else
            {
                toolStripStatusLabel1.Text = "Buzzer konnte nicht aktiviert werden!";
            }
        }

        private void deaktiviertToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (setBuzzer(false))
            {
                toolStripStatusLabel1.Text = "Buzzer deaktiviert";
            }
            else
            {
                toolStripStatusLabel1.Text = "Buzzer konnte nicht deaktiviert werden!";
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            textBox1.AppendText(BitConverter.ToString(getUID()) + "\n");
        }

        private void button2_Click(object sender, EventArgs e)
        {
            var Data = new byte[1024];
            Data = readCard();
            cardByteProvider = new DynamicByteProvider(Data);
            hexBox1.ByteProvider = cardByteProvider;
        }

        private cardtype detectATR(byte[] atr)
        {
            if (atr.ToString().Contains(Mifare1K.ToString()))
            {
                return cardtype.Mifare1K;
            }
            else if (atr.ToString().Contains(Mifare4K.ToString()))
            {
                return cardtype.Mifare4K;
            } else if (atr.ToString().Contains(MifareUL.ToString()))
            {
                return cardtype.MifareUL;
            } else if (atr.ToString().Contains(MifareMi.ToString())) {
                return cardtype.MifareMi;
            } else if (atr.ToString().Contains(TopazJwl.ToString())) {
                return cardtype.ToapzJwl;
            } else if (atr.ToString().Contains(FeliCa212.ToString())) {
                return cardtype.FeliCa212;
            } else if (atr.ToString().Contains(FeliCa424.ToString())) {
                return cardtype.FeliCa424;
            } else if (atr.ToString().Contains(DESFire.ToString())) {
                return cardtype.DESFire;
            } else
            {
                return cardtype.Unknown;
            }
        }

        private void versionToolStripMenuItem_Click(object sender, EventArgs e)
        {
            MessageBox.Show("DoorAdmin " + swVersion);
        }
    }

}
