---
author:
  email: doop3lgang3r@gmail.com
  github: https://github.com/Doopel
  image:
  - /images/Doopel_Profile/dopelrIcon.png
  name:
  - Doopel

cardtitlecolor: 'orange'
post_categories:
- RF
- Reversing
date: 2017-09-01T18:56:18+02:00
description: a
tags:
- test
title: "Garage door RF communication"
summary: "Reversing an unknown radio signal protocol "
cardthumbimage: "/assets/Garage_Door_RF_communication/ProtocolRerversing/title.jpg"
cardbackground: '#FFF'
---

## Abstract 

This the first of a serie of post where we are going to revese engineered a garage radio control to undertand how it works. In this first post we will describe how we have proceed in order to revese engineered the signal, present our first conclusions about our findings and which are going to be our next steps to hack the device.

This summer I wanted to introduce my self into the security RF world and what better way than take the first RF device that we have in our home and take a look how it works. We are writing this post to help those like us want to start in the radio security world explaing how we have start and proced to do our first investigation in a real device.

We highly recommened to take a look to [Michael Ossmann's video classes](https://greatscottgadgets.com/sdr/) to get introduceded into the SDR wolrd. In this post we have used a software named *Universal Hacker Radio (UHR)* because it provides multiple useful fuctionalities such as:

- Spectrum analyser
- Recording
- Oscilloscope view
- Analyze interface  

## Indentify the signal frequency 

To begin it is necesary to discove in which frequency the device is working. I recommened to check if your device is in [FCCID database] (https://fccid.io/). It is a unique identifier assigned to a device registered with the United States Federal Communications Commission. Unfortunatly in our case it was not registed so we dig a little bit around Internet and we found that the device play around the 868 KHz.

In order to check it **UHR** has an spectrum analyzer functionality but I prefer to used the  **osmocom_fft** tool. 
![Spectrum analyzer](/assets/Garage_Door_RF_communication/ProtocolRerversing/Finding-Signal.png)

#### Tips ####

- To visulize properlly the signal, set the frequecy a little bit lower or higher that the one which you are checking.
- Check the peak hold option
- Send multiple signal to confirm that it is the signal that you are looking for.
- Remenber the **HackRF** has a limit of 2M samples per rate.

## Recording the signal

To record the packges I like to used the *URH* recording tool because it show you in real time what are you recoding and it add the record stream automatically to the analysis tab.  

## Signal analysis

There are two esential things that it is necesary to know about the signal, which kind of modulation has been used and which is the bit legth/symbol length.
Taking a look to the recorded signal and zooming in we can say that the signal looks like, it is a form of amplitude modulation that represents digital data, specifically it is *On-Off-keys* modulation. It is the simplest form of *amplitude-shift keying (ASK)* modulation that represents digital data at the presence or absence of a carrier wave.In its simplest form, the presence of a carrier for a specific duration represents a binary one, while its absence for the same duration represents a binary zero.
![Raw stream](/assets/Garage_Door_RF_communication/ProtocolRerversing/RawStream.png)
![Raw stream 2](/assets/Garage_Door_RF_communication/ProtocolRerversing/RawStream2.png)
![Raw stream 3](/assets/Garage_Door_RF_communication/ProtocolRerversing/RawStream3.png)

Now that we know what kind of modulation has been used it is easy to calculate the bit lenght using *URH* as is shown. Selecting manually the area and introducing the value into the proper box. Another really useful thing is that in the bottom it is displayed the stream in bits, hex or ASCII.
![Bit lenght ](/assets/Garage_Door_RF_communication/ProtocolRerversing/BitLenght.png)

## Reversing the communication protocol
Now we can procude to the analysis tab to reverse enginired the protocol. The first thing I like to do is to chage the view to hexadecimal.
![Analysis interface](/assets/Garage_Door_RF_communication/ProtocolRerversing/AnalysisInterface.png)

## Next step

## Tools used:
* [HackRF](https://greatscottgadgets.com/hackrf/)
* [Universal hacker radio] (https://github.com/sthysel/urh)
* [osmocom_fft] (https://github.com/osmocom/gr-osmosdr)



